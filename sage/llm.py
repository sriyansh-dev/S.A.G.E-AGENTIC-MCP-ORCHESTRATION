"""Groq chat-completions client (OpenAI-compatible) with backoff, JSON repair and a tool-calling loop."""
import json
import re
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx
from pydantic import BaseModel, SecretStr, ValidationError

from .redact import SecretRegistry
from .retry import RetryableError, with_backoff

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
M = TypeVar("M", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class ModelUnavailable(LLMError):
    pass


class JsonModeFailed(LLMError):
    pass


class ParamRejected(LLMError):
    pass


MODELS_URL = "https://api.groq.com/openai/v1/models"
_EXCLUDE = re.compile(r"whisper|tts|guard|embed|compound|orpheus|safeguard|moderation|distil|vision|preview", re.I)
_PREFS = [r"llama-3\.3-70b", r"gpt-oss-120b", r"qwen.*(?:32b|27b)", r"gpt-oss-20b", r"llama-3\.1-8b", r"."]


def rank_models(ids: list[str]) -> list[str]:
    usable = [i for i in ids if not _EXCLUDE.search(i)]
    out: list[str] = []
    for pat in _PREFS:
        out += [i for i in sorted(usable) if re.search(pat, i) and i not in out]
    return out


def _retry_after(r: httpx.Response) -> float | None:
    v = r.headers.get("retry-after")
    try:
        return float(v) if v else None
    except ValueError:
        return None


def extract_json(text: str) -> str:
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    s, e = t.find("{"), t.rfind("}")
    if s == -1 or e <= s:
        raise ValueError("no JSON object found")
    return t[s: e + 1]


class GroqClient:
    def __init__(self, api_key: SecretStr, model: str, registry: SecretRegistry | None = None,
                 http: httpx.AsyncClient | None = None, max_attempts: int = 7) -> None:
        self._key = api_key
        self.model = model
        self._reg = registry or SecretRegistry()
        self._reg.add(api_key.get_secret_value())
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0))
        self._own = http is None
        self._attempts = max_attempts
        self.calls = 0
        self.candidates: list[str] = [model]
        self._no_reasoning = False
        self.log = lambda m: None  # set by the CLI so rate-limit waits are visible

    async def resolve_model(self, preferred: str | None = None) -> str:
        """Ask Groq which models THIS key can use and pick the best; falls back to rotation on 404."""
        async def once() -> list[str]:
            try:
                r = await self._http.get(MODELS_URL, headers={"Authorization": f"Bearer {self._key.get_secret_value()}"})
            except (httpx.TimeoutException, httpx.TransportError) as e:
                raise RetryableError(type(e).__name__) from None
            if r.status_code == 401:
                raise LLMError("Groq rejected the API key (HTTP 401)")
            if r.status_code != 200:
                raise RetryableError(f"HTTP {r.status_code}", _retry_after(r))
            return [m["id"] for m in r.json().get("data", []) if m.get("active", True)]
        ids = await with_backoff(once, attempts=4, base=1.5)
        ranked = rank_models(ids)
        if preferred and preferred in ids:
            ranked.insert(0, preferred)
        if not ranked:
            raise LLMError("this Groq key has no usable chat models")
        self.candidates, self.model = ranked, ranked[0]
        return self.model

    def _rotate(self) -> bool:
        self.candidates = [m for m in self.candidates if m != self.model]
        if not self.candidates:
            return False
        self.model = self.candidates[0]
        return True

    async def aclose(self) -> None:
        if self._own:
            await self._http.aclose()

    async def _post(self, payload: dict) -> dict:
        async def once() -> dict:
            try:
                r = await self._http.post(GROQ_URL, json=payload,
                                          headers={"Authorization": f"Bearer {self._key.get_secret_value()}"})
            except (httpx.TimeoutException, httpx.TransportError) as e:
                raise RetryableError(f"transport error: {type(e).__name__}") from None
            if r.status_code == 200:
                return r.json()
            body = r.text[:600]
            ra = _retry_after(r)
            if r.status_code == 429 and ((ra is not None and ra > 30) or re.search(
                    r"tokens per day|requests per day|\bTPD\b|\bRPD\b", body, re.I)):
                wait = f"{ra:.0f}s" if ra else "a long time"
                raise ModelUnavailable(f"rate limit on {payload.get('model')}: retry in {wait}")
            if r.status_code in (408, 409, 425, 429, 500, 502, 503, 504) or (
                    r.status_code == 400 and "tool_use_failed" in body):
                raise RetryableError(f"HTTP {r.status_code}", _retry_after(r))
            if r.status_code == 401:
                raise LLMError("Groq rejected the API key (HTTP 401)")
            if r.status_code in (400, 403, 404) and re.search(
                    r"model_not_found|does not exist|decommission|model_permission|not have access", body, re.I):
                raise ModelUnavailable(f"model {payload.get('model')} unavailable for this key")
            if r.status_code == 400 and re.search(r"Failed to generate JSON|json_validate_failed|failed_generation",
                                                  body, re.I):
                raise JsonModeFailed(body)
            if r.status_code == 400 and "reasoning" in body.lower():
                raise ParamRejected(body)
            raise LLMError(f"Groq HTTP {r.status_code}: {self._reg.redact(body)}")

        self.calls += 1
        try:
            return await with_backoff(once, attempts=self._attempts, base=1.5, cap=45,
                                      on_retry=lambda i, d, e: self.log(f"  Groq busy ({e}); retry {i} in {d:.0f}s"))
        except RetryableError as e:
            raise LLMError(f"Groq unavailable after {self._attempts} attempts: {e}") from None

    async def chat(self, messages: list[dict], *, tools: list[dict] | None = None, json_mode: bool = False,
                   temperature: float = 0.1, max_tokens: int = 4096) -> dict:
        payload: dict = {"model": self.model, "messages": messages, "temperature": temperature,
                         "max_tokens": max_tokens}
        if tools:
            payload.update(tools=tools, tool_choice="auto")
        elif json_mode:
            payload["response_format"] = {"type": "json_object"}
        while True:
            payload["model"] = self.model
            if "gpt-oss" in self.model and not self._no_reasoning:
                payload["reasoning_effort"] = "low"  # faster demo runs; JSON output does not need deep reasoning
            else:
                payload.pop("reasoning_effort", None)
            try:
                data = await self._post(payload)
                break
            except ModelUnavailable as e:
                self.log(f"  {e} - switching model")
                if not self._rotate():
                    raise LLMError(f"{e}. No other Groq model left to try; wait and rerun, or use another key.") from None
            except ParamRejected:
                if "reasoning_effort" not in payload:
                    raise
                self._no_reasoning = True
            except JsonModeFailed:
                if "response_format" not in payload:
                    raise
                payload.pop("response_format")  # retry in plain mode; chat_model() extracts + validates the JSON
                payload["messages"] = payload["messages"] + [{
                    "role": "user", "content": "Reply with ONLY one valid JSON object. No prose, no markdown fences."}]
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError):
            raise LLMError("malformed Groq response") from None

    async def chat_model(self, messages: list[dict], model_cls: type[M], *, tries: int = 3) -> M:
        msgs = list(messages)
        last = ""
        for _ in range(tries):
            msg = await self.chat(msgs, json_mode=True)
            text = msg.get("content") or ""
            try:
                return model_cls.model_validate_json(extract_json(text))
            except (ValueError, ValidationError) as e:
                last = str(e)[:800]
                msgs += [{"role": "assistant", "content": text[:4000]},
                         {"role": "user", "content": f"Invalid output: {last}\nReturn corrected JSON only."}]
        raise LLMError(f"model did not produce valid {model_cls.__name__}: {last}")

    async def run_with_tools(self, messages: list[dict], tools: list[dict],
                             call_tool: Callable[[str, dict], Awaitable[str]], *, max_rounds: int = 6) -> list[dict]:
        msgs = list(messages)
        for _ in range(max_rounds):
            m = await self.chat(msgs, tools=tools)
            calls = m.get("tool_calls")
            if not calls:
                msgs.append({"role": "assistant", "content": m.get("content") or ""})
                return msgs
            msgs.append({"role": "assistant", "content": m.get("content"), "tool_calls": calls})
            for c in calls:
                try:
                    args = json.loads(c["function"].get("arguments") or "{}")
                    out = await call_tool(c["function"]["name"], args)
                except Exception as e:  # noqa: BLE001 — tool errors go back to the model
                    out = f"ERROR: {self._reg.redact(str(e))[:500]}"
                msgs.append({"role": "tool", "tool_call_id": c["id"], "content": out[:8000]})
        return msgs
