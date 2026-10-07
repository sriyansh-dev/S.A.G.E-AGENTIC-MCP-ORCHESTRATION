"""MCP client used by the orchestrator. Spawns the local MCP server over stdio."""
import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, TypeVar

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel

from .schemas import (AnalyticsOutput, AnalyzeCodebaseInput, ApplyPatchesInput, ApplyPatchesOutput, CommitPRInput, CommitPROutput, FileEdit,
                      ListRepoFilesOutput, ReadRepoFileInput, ReadRepoFileOutput, ReportInput, ReportOutput,
                      RequestCredentialInput, RequestCredentialOutput, RevertPatchesOutput, RunTestsInput,
                      RunTestsOutput, ScanCredentialsInput, ScanCredentialsOutput)

M = TypeVar("M", bound=BaseModel)
ROOT = Path(__file__).resolve().parent.parent
PASS_ENV = ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
            "XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XAUTHORITY",
            "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK")  # no GROQ_API_KEY


class ToolCallError(RuntimeError):
    pass


def _inline_refs(schema: dict, defs: dict) -> Any:
    if isinstance(schema, dict):
        if "$ref" in schema:
            return _inline_refs(defs[schema["$ref"].split("/")[-1]], defs)
        return {k: _inline_refs(v, defs) for k, v in schema.items() if k != "$defs"}
    if isinstance(schema, list):
        return [_inline_refs(x, defs) for x in schema]
    return schema


class McpBridge:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self._stack = AsyncExitStack()
        self._s: ClientSession | None = None
        self._wrapped: dict[str, bool] = {}
        self._tools: dict[str, dict] = {}

    async def __aenter__(self) -> "McpBridge":
        env = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
        env.update(SAGE_WORKSPACE=str(self.workspace), PYTHONPATH=str(ROOT))
        params = StdioServerParameters(command=sys.executable, args=["-m", "sage.mcp_server"], env=env, cwd=str(ROOT))
        r, w = await self._stack.enter_async_context(stdio_client(params))
        self._s = await self._stack.enter_async_context(ClientSession(r, w))
        await self._s.initialize()
        for t in (await self._s.list_tools()).tools:
            props = (t.inputSchema or {}).get("properties", {})
            self._wrapped[t.name] = list(props) == ["params"]
            self._tools[t.name] = {"description": t.description or "", "schema": t.inputSchema or {}}
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._stack.aclose()

    def llm_tools(self, allow: set[str]) -> list[dict]:
        out = []
        for name in sorted(allow & set(self._tools)):
            sch = self._tools[name]["schema"]
            defs = sch.get("$defs", {})
            if self._wrapped[name]:
                sch = sch["properties"]["params"]
            sch = _inline_refs(sch, defs) if sch else {"type": "object", "properties": {}}
            out.append({"type": "function", "function": {"name": name, "description": self._tools[name]["description"][:300],
                                                         "parameters": sch or {"type": "object", "properties": {}}}})
        return out

    async def call(self, name: str, args: dict | None = None) -> dict:
        assert self._s
        if name not in self._tools:
            raise ToolCallError(f"unknown tool {name}")
        payload = {"params": args or {}} if self._wrapped[name] else (args or {})
        res = await self._s.call_tool(name, payload)
        if res.isError:
            raise ToolCallError(" ".join(getattr(c, "text", "") for c in res.content)[:800])
        if getattr(res, "structuredContent", None):
            return res.structuredContent
        return json.loads(res.content[0].text)

    async def call_as_text(self, name: str, args: dict) -> str:
        return json.dumps(await self.call(name, args), separators=(",", ":"))[:8000]

    async def _typed(self, name: str, model: type[M], inp: BaseModel | None = None) -> M:
        return model.model_validate(await self.call(name, inp.model_dump(mode="json") if inp else {}))

    async def scan(self) -> ScanCredentialsOutput:
        return await self._typed("scan_codebase_credentials", ScanCredentialsOutput, ScanCredentialsInput())

    async def analyze(self) -> AnalyticsOutput:
        return await self._typed("analyze_codebase", AnalyticsOutput, AnalyzeCodebaseInput())

    async def request_credential(self, name: str, purpose: str) -> RequestCredentialOutput:
        return await self._typed("request_user_credential", RequestCredentialOutput,
                                 RequestCredentialInput(name=name, purpose=purpose))

    async def run_tests(self, **kw: Any) -> RunTestsOutput:
        return await self._typed("run_tests_and_verify", RunTestsOutput, RunTestsInput(**kw))

    async def apply_patches(self, edits: list[FileEdit]) -> ApplyPatchesOutput:
        return await self._typed("apply_patches", ApplyPatchesOutput, ApplyPatchesInput(edits=edits))

    async def revert(self) -> RevertPatchesOutput:
        return await self._typed("revert_patches", RevertPatchesOutput)

    async def read_file(self, path: str, **kw: Any) -> ReadRepoFileOutput:
        return await self._typed("read_repo_file", ReadRepoFileOutput, ReadRepoFileInput(path=path, **kw))

    async def list_files(self, glob: str = "**/*", limit: int = 200) -> ListRepoFilesOutput:
        return ListRepoFilesOutput.model_validate(await self.call("list_repo_files", {"glob": glob, "limit": limit}))

    async def report(self, rep: ReportInput) -> ReportOutput:
        return await self._typed("generate_detailed_report", ReportOutput, rep)

    async def publish(self, inp: CommitPRInput) -> CommitPROutput:
        return await self._typed("commit_and_open_pr", CommitPROutput, inp)
