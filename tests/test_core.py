import asyncio
import json
import textwrap
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from sage.dag import DagError, DagScheduler, Node, NonRetryable, Status
from sage.llm import GroqClient, LLMError
from sage.redact import SecretRegistry
from sage.runner import build_install_script, parse_pytest
from sage.scanner import scan_workspace
from sage.schemas import ApplyPatchesInput, FileEdit, Plan
from sage.tools import Toolbox

FAKE_OPENAI = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"


def make_repo(tmp: Path) -> Path:
    (tmp / "app.py").write_text(textwrap.dedent(f'''
        import os, subprocess, yaml, requests
        from os import getenv
        KEY = "STRIPE_KEY"
        DB = os.environ["DATABASE_URL"]
        tok = os.environ.get("API_TOKEN", "x")
        s = os.environ[KEY]
        n = getenv("OPTIONAL_THING")
        OPENAI = "{FAKE_OPENAI}"
        def f(cmd, cur):
            subprocess.run(cmd, shell=True)
            cur.execute("select * from t where id=%s" % cmd)
            yaml.load(open("x"))
            return requests.get("http://x")
        '''))
    (tmp / "web.js").write_text("const k = process.env.NEXT_SECRET_KEY;\n")
    (tmp / ".env.example").write_text("SMTP_PASSWORD=\n")
    (tmp / ".env").write_text("REAL=gsk_" + "Z" * 30 + "\n")
    return tmp


def test_scanner_finds_everything_and_never_leaks(tmp_path):
    reg = SecretRegistry()
    out = scan_workspace(make_repo(tmp_path), reg)
    names = {e.name: e for e in out.env_vars}
    assert names["DATABASE_URL"].required and names["DATABASE_URL"].confidence >= 0.9
    assert not names["API_TOKEN"].required
    assert "STRIPE_KEY" in names and "OPTIONAL_THING" in names
    assert "NEXT_SECRET_KEY" in names and "SMTP_PASSWORD" in names
    assert "REAL" not in names  # real .env never read
    rules = {v.rule_id for v in out.vulnerabilities}
    assert {"PY-SHELL", "PY-SQLI", "PY-YAML-LOAD", "PY-NO-TIMEOUT", "SECRET-OPENAI-KEY"} <= rules
    dumped = out.model_dump_json()
    assert FAKE_OPENAI not in dumped and "ZZZZ" not in dumped
    assert reg.leaks(FAKE_OPENAI) == 1


def test_redact_mask_roundtrip():
    reg = SecretRegistry()
    reg.add("hunter2hunter2")
    t = f"pw=hunter2hunter2 key={FAKE_OPENAI}"
    assert "hunter2" not in reg.redact(t) and FAKE_OPENAI not in reg.redact(t)
    m = reg.mask(t)
    assert "{{SAGE_SECRET_" in m and reg.unmask(m) == t


def test_apply_patches_atomic_and_revert(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
    tb = Toolbox(tmp_path)

    async def go():
        bad = await tb.apply_patches(ApplyPatchesInput(edits=[
            FileEdit(path="a.py", search="x = 1", replace="x = 10"),
            FileEdit(path="a.py", search="nope", replace="z")]))
        assert not bad.applied and (tmp_path / "a.py").read_text() == "x = 1\ny = 2\n"
        syn = await tb.apply_patches(ApplyPatchesInput(edits=[FileEdit(path="a.py", search="x = 1", replace="x = (")]))
        assert not syn.applied and "syntax" in syn.errors[0]
        ok = await tb.apply_patches(ApplyPatchesInput(edits=[
            FileEdit(path="a.py", search="x = 1  \n", replace="x = 10\n"),  # whitespace-tolerant
            FileEdit(path="new.py", replace="print(1)\n")]))
        assert ok.applied and "+x = 10" in ok.diff
        assert (tmp_path / "new.py").exists()
        rv = await tb.revert_patches()
        assert (tmp_path / "a.py").read_text() == "x = 1\ny = 2\n" and not (tmp_path / "new.py").exists()
        assert sorted(rv.reverted_files) == ["a.py", "new.py"]
    asyncio.run(go())


def test_path_validation():
    for p in ("../x", "/etc/passwd", ".git/config", ".env", "a/../../b"):
        with pytest.raises(ValueError):
            FileEdit(path=p, replace="x")
    FileEdit(path=".env.example", replace="x")
    with pytest.raises(ValueError):
        Plan(summary="s", hypotheses=[], target_files=["../x"])


def test_dag_order_parallel_skip_and_cycle():
    log = []

    def mk(name, fail=False, delay=0.05):
        async def fn():
            log.append(("start", name))
            await asyncio.sleep(delay)
            if fail:
                raise NonRetryable("boom")
            log.append(("end", name))
        return fn

    nodes = [Node("a", mk("a")), Node("b", mk("b"), ("a",)), Node("c", mk("c"), ("a",)),
             Node("d", mk("d", fail=True), ("b", "c")), Node("e", mk("e"), ("d",)),
             Node("f", mk("f"), ("d",), tolerate=frozenset({"d"}))]
    res = asyncio.run(DagScheduler(nodes).run())
    s = {k: v.status for k, v in res.nodes.items()}
    assert s["a"] == s["b"] == s["c"] == s["f"] == Status.succeeded
    assert s["d"] == Status.failed and s["e"] == Status.skipped
    assert log.index(("start", "c")) < log.index(("end", "b"))  # b and c overlapped
    with pytest.raises(DagError):
        DagScheduler([Node("x", mk("x"), ("y",)), Node("y", mk("y"), ("x",))])


def test_dag_retries():
    n = {"i": 0}

    async def flaky():
        n["i"] += 1
        if n["i"] < 2:
            raise RuntimeError("once")
    res = asyncio.run(DagScheduler([Node("x", flaky, retries=2)]).run())
    assert res.nodes["x"].status == Status.succeeded and res.nodes["x"].attempts == 2


def test_parse_pytest():
    s = parse_pytest("...\n2 failed, 10 passed, 1 skipped in 2.50s\n", 1, 2.5, False)
    assert (s.passed, s.failed, s.skipped, s.collected) == (10, 2, 1, 13)
    assert parse_pytest("no tests ran in 0.01s", 5, 0.1, False).collected == 0


def test_llm_backoff_json_repair_and_key_hygiene(monkeypatch):
    import sage.retry as r

    async def nosleep(_):
        pass
    monkeypatch.setattr(r.asyncio, "sleep", nosleep)
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert req.headers["authorization"] == "Bearer gsk_secretsecretsecretsecret"
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, text="slow down")
        if calls["n"] == 2:
            return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})
        body = json.dumps({"summary": "s", "hypotheses": [], "target_files": ["a.py"], "risk": "low"})
        return httpx.Response(200, json={"choices": [{"message": {"content": f"```json\n{body}\n```"}}]})

    async def go():
        c = GroqClient(SecretStr("gsk_secretsecretsecretsecret"), "m",
                       http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        plan = await c.chat_model([{"role": "user", "content": "x"}], Plan)
        assert plan.target_files == ["a.py"] and calls["n"] == 3

        def bad(req):
            return httpx.Response(401, text="invalid gsk_secretsecretsecretsecret")
        c2 = GroqClient(SecretStr("gsk_secretsecretsecretsecret"), "m",
                        http=httpx.AsyncClient(transport=httpx.MockTransport(bad)))
        with pytest.raises(LLMError) as ei:
            await c2.chat([{"role": "user", "content": "x"}])
        assert "gsk_secret" not in str(ei.value)
    asyncio.run(go())


def test_install_script_is_fish_syntax(tmp_path):
    import shutil
    import subprocess
    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "pyproject.toml").write_text("")
    script = build_install_script(tmp_path)
    assert "; or" in script and "&&" not in script
    if shutil.which("fish"):
        r = subprocess.run(["fish", "--no-config", "--no-execute", "-c", script], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_model_discovery_and_rotation():
    from sage.llm import rank_models

    ids = ["whisper-large-v3", "llama-3.1-8b-instant", "openai/gpt-oss-120b", "llama-3.3-70b-versatile",
           "meta-llama/llama-guard-4-12b", "playai-tts", "groq/compound"]
    assert rank_models(ids) == ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "llama-3.1-8b-instant"]
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": i} for i in ids]})
        m = json.loads(req.content)["model"]
        seen.append(m)
        if m == "llama-3.3-70b-versatile":
            return httpx.Response(404, text='{"error":{"message":"The model `x` does not exist or you do not have access to it."}}')
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    async def go():
        c = GroqClient(SecretStr("gsk_" + "k" * 30), "llama-3.3-70b-versatile",
                       http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        assert await c.resolve_model() == "llama-3.3-70b-versatile"
        msg = await c.chat([{"role": "user", "content": "x"}])
        assert msg["content"] == "hi" and c.model == "openai/gpt-oss-120b"
        assert seen == ["llama-3.3-70b-versatile", "openai/gpt-oss-120b"]
    asyncio.run(go())


def test_analytics(tmp_path):
    from sage.analytics import analyze_workspace
    (tmp_path / "a.py").write_text("def f(x):\n    if x:\n        for i in x:\n            pass\n    return 1  # TODO\n")
    (tmp_path / "test_a.py").write_text("def test_f():\n    pass\n")
    (tmp_path / "requirements.txt").write_text("x\n")
    a = analyze_workspace(tmp_path)
    assert a.python_functions == 2 and a.hotspots[0].name == "f" and a.hotspots[0].complexity == 3
    assert a.has_tests and a.todo_count == 1 and "requirements.txt" in a.dependency_files


def test_json_mode_failure_falls_back_to_plain_mode_and_drops_bad_reasoning_param(monkeypatch):
    import sage.retry as r

    async def nosleep(_):
        pass
    monkeypatch.setattr(r.asyncio, "sleep", nosleep)
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(("response_format" in body, body.get("reasoning_effort")))
        if len(seen) == 1:
            return httpx.Response(400, text='{"error":{"message":"reasoning_effort is not supported"}}')
        if "response_format" in body:
            return httpx.Response(400, text='{"error":{"message":"Failed to generate JSON. See failed_generation"}}')
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"summary":"s","hypotheses":[],"target_files":["a.py"]}'}}]})

    async def go():
        c = GroqClient(SecretStr("gsk_" + "k" * 30), "openai/gpt-oss-120b",
                       http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        plan = await c.chat_model([{"role": "user", "content": "x"}], Plan)
        assert plan.target_files == ["a.py"]
        assert seen[0] == (True, "low") and seen[1] == (True, None) and seen[2] == (False, None)
    asyncio.run(go())


def test_entrypoint_found_in_subfolder(tmp_path):
    from sage.runner import find_entrypoint
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "dashboard.py").write_text("def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
    (tmp_path / "proj" / "test_x.py").write_text("if __name__ == '__main__': pass\n")
    assert find_entrypoint(tmp_path) == "proj/dashboard.py"


def test_long_rate_limit_rotates_model_instead_of_waiting():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        m = json.loads(req.content)["model"]
        seen.append(m)
        if m == "model-a":
            return httpx.Response(429, headers={"retry-after": "600"}, text="rate limit")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    async def go():
        c = GroqClient(SecretStr("gsk_" + "k" * 30), "model-a", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        c.candidates = ["model-a", "model-b"]
        logs = []
        c.log = logs.append
        assert (await c.chat([{"role": "user", "content": "x"}]))["content"] == "ok"
        assert seen == ["model-a", "model-b"] and "switching model" in logs[0]
        c2 = GroqClient(SecretStr("gsk_" + "k" * 30), "model-a", http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(429, headers={"retry-after": "600"}, text="x"))))
        with pytest.raises(LLMError) as ei:
            await c2.chat([{"role": "user", "content": "x"}])
        assert "No other Groq model" in str(ei.value)
    asyncio.run(go())
