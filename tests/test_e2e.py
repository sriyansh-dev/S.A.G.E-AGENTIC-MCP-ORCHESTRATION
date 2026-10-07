import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

import sage.pipeline as pl
from sage.bridge import McpBridge
from sage.llm import GroqClient
from sage.pipeline import Pipeline, Settings
from sage.redact import SecretRegistry
from sage.schemas import RunTestsInput
from sage.tools import Toolbox

pytestmark = pytest.mark.skipif(not shutil.which("fish") or not shutil.which("python"), reason="needs fish+python on PATH")


def make_buggy_repo(p: Path) -> Path:
    p.mkdir(parents=True)
    (p / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    (p / "test_calc.py").write_text("from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n\ndef test_zero():\n    assert add(0, 0) == 0\n")
    run = lambda *a: subprocess.run(a, cwd=p, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "remote", "add", "origin", "https://github.com/octo/demo.git")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return p


def test_toolbox_runs_tests_in_fish_venv(tmp_path):
    repo = make_buggy_repo(tmp_path / "r")
    tb = Toolbox(repo)
    out = asyncio.run(tb.run_tests_and_verify(RunTestsInput(label="baseline", runs=2)))
    assert out.install_ok and out.tests_found and not out.all_passed
    assert out.runs[-1].failed == 1 and out.runs[-1].passed == 1 and not out.flaky
    assert "test_add" in out.log_tail


def groq_handler(state):
    def h(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        sys_p = body["messages"][0]["content"]
        msg = lambda c=None, tc=None: httpx.Response(200, json={"choices": [{"message": {"content": c, "tool_calls": tc}}]})
        if sys_p.startswith("You are the Code Auditor"):
            return msg(json.dumps({"summary": "Small app with one arithmetic bug.", "strengths": ["tiny surface"],
                                   "issues": [{"severity": "high", "file": "calc.py", "detail": "add() subtracts", "suggestion": "use +"}],
                                   "optimizations": ["none needed"]}))
        if sys_p.startswith("You are the Planner"):
            if body.get("tools"):
                state["tools_seen"] = [t["function"]["name"] for t in body["tools"]]
                if not any(m["role"] == "tool" for m in body["messages"]):
                    return msg(None, [{"id": "c1", "type": "function", "function": {
                        "name": "read_repo_file", "arguments": json.dumps({"path": "calc.py"})}}])
                return msg("done investigating")
            return msg(json.dumps({"summary": "add() subtracts", "hypotheses": [{"title": "wrong operator", "evidence": "a - b", "files": ["calc.py"]}],
                                   "target_files": ["calc.py"], "risk": "low"}))
        if sys_p.startswith("You are the Patcher"):
            state["patch_calls"] += 1
            repl = "a * b" if state["patch_calls"] == 1 else "a + b"   # first attempt is wrong → must be rejected by tests
            return msg(json.dumps({"rationale": f"use {repl}", "addresses": ["wrong operator"],
                                   "edits": [{"path": "calc.py", "search": "return a - b", "replace": f"return {repl}"}]}))
        if sys_p.startswith("You are the Reviewer"):
            return msg(json.dumps({"approved": True, "risk": "low", "issues": [], "summary": "minimal operator fix"}))
        return httpx.Response(500)
    return h


def test_full_pipeline_rejects_bad_patch_then_accepts_verified_one(tmp_path, monkeypatch):
    src = make_buggy_repo(tmp_path / "src")

    async def fake_clone(url, dest, registry, token):
        subprocess.run(["git", "clone", "-q", str(src), str(dest)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/octo/demo.git"], cwd=dest, check=True)
        return "main"
    async def no_token():
        return None
    monkeypatch.setattr(pl, "clone", fake_clone)
    monkeypatch.setattr(pl, "github_token", no_token)
    state = {"patch_calls": 0}
    logs: list[str] = []
    ws = tmp_path / "ws"
    ws.mkdir()
    reg = SecretRegistry()
    llm = GroqClient(SecretStr("gsk_" + "k" * 30), "m", reg, http=httpx.AsyncClient(transport=httpx.MockTransport(groq_handler(state))))
    settings = Settings(groq_key=SecretStr("x"), runs=2, max_iterations=3, dry_run=True, log=logs.append,
                        direct_plan_max_files=0)  # force the tool-calling planner path here

    async def go():
        async with McpBridge(ws) as bridge:
            p = Pipeline("https://github.com/octo/demo", "fix add()", ws, bridge, llm, settings, reg)
            return p, await p.run()
    p, res = asyncio.run(go())
    assert res.ok, {k: (v.status, v.error) for k, v in res.nodes.items()}
    st = p.state
    assert st.accepted and [a.outcome for a in st.attempts] == ["tests_failed", "accepted"]
    assert set(state["tools_seen"]) == {"scan_codebase_credentials", "list_repo_files", "read_repo_file"}
    assert st.pr and st.pr.success and st.pr.branch_name.startswith("sage/") and st.pr.pushed_to is None
    log = subprocess.run(["git", "log", "-1", "--stat", "--format=%s"], cwd=ws, capture_output=True, text=True).stdout
    assert "calc.py" in log and "SAGE_REPORT.md" in log and ".env" not in log
    assert "return a + b" in (ws / "calc.py").read_text()
    report = (ws / "SAGE_REPORT.md").read_text()
    assert "VERIFIED" in report and "| Tests failed | 1 | 0 |" in report
    assert "## Code analytics" in report and "## Code review" in report and "add() subtracts" in report


def test_commit_refuses_secret_in_diff(tmp_path):
    repo = make_buggy_repo(tmp_path / "r")
    (repo / "calc.py").write_text("KEY = 'gsk_" + "Q" * 30 + "'\n")
    (repo / "SAGE_REPORT.md").write_text("r")
    from sage.schemas import CommitPRInput
    out = asyncio.run(Toolbox(repo).commit_and_open_pr(CommitPRInput(
        branch_suffix="x", commit_message="m", pr_title="t", report_path="SAGE_REPORT.md", files=["calc.py"], push=False)))
    assert not out.success and "secret" in out.error and "QQQQ" not in out.error
    staged = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=repo, capture_output=True, text=True).stdout
    assert staged == ""


def make_untested_repo(p: Path) -> Path:
    p.mkdir(parents=True)
    (p / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n")
    run = lambda *a: subprocess.run(a, cwd=p, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "remote", "add", "origin", "https://github.com/octo/untested.git")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return p


def static_handler(state):
    def h(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        sys_p = body["messages"][0]["content"]
        msg = lambda c: httpx.Response(200, json={"choices": [{"message": {"content": c}}]})
        if sys_p.startswith("You are the Code Auditor"):
            return msg(json.dumps({"summary": "Small app with one arithmetic bug.", "strengths": ["tiny surface"],
                                   "issues": [{"severity": "high", "file": "calc.py", "detail": "add() subtracts", "suggestion": "use +"}],
                                   "optimizations": ["none needed"]}))
        if sys_p.startswith("You are the Planner"):
            if body.get("tools"):
                return msg("ok")
            return msg(json.dumps({"summary": "shell=True", "hypotheses": [], "target_files": ["app.py"], "risk": "low"}))
        if sys_p.startswith("You are the Patcher"):
            state["n"] += 1
            # attempt 1 changes nothing meaningful for the scanner (still shell=True) → rejected; attempt 2 fixes it
            new = "subprocess.run(cmd, shell=True)  # ok" if state["n"] == 1 else "subprocess.run(cmd.split())"
            return msg(json.dumps({"rationale": "avoid shell", "edits": [
                {"path": "app.py", "search": "subprocess.run(cmd, shell=True)", "replace": new}]}))
        return msg(json.dumps({"approved": True, "risk": "low", "issues": [], "summary": "ok"}))
    return h


def test_static_mode_for_repo_without_tests(tmp_path, monkeypatch):
    src = make_untested_repo(tmp_path / "src")

    async def fake_clone(url, dest, registry, token):
        subprocess.run(["git", "clone", "-q", str(src), str(dest)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/octo/untested.git"], cwd=dest, check=True)
        return "main"
    async def no_token():
        return None
    monkeypatch.setattr(pl, "clone", fake_clone)
    monkeypatch.setattr(pl, "github_token", no_token)
    ws = tmp_path / "ws"
    ws.mkdir()
    reg = SecretRegistry()
    st_ = {"n": 0}
    llm = GroqClient(SecretStr("gsk_" + "k" * 30), "m", reg, http=httpx.AsyncClient(transport=httpx.MockTransport(static_handler(st_))))
    settings = Settings(groq_key=SecretStr("x"), runs=1, max_iterations=3, dry_run=True, log=lambda m: None)

    async def go():
        async with McpBridge(ws) as bridge:
            p = Pipeline("https://github.com/octo/untested", "fix vulnerabilities", ws, bridge, llm, settings, reg)
            return p, await p.run()
    p, res = asyncio.run(go())
    assert res.ok, {k: (v.status, v.error) for k, v in res.nodes.items()}
    assert p.state.verification == "static" and p.state.accepted
    assert [a.outcome for a in p.state.attempts] == ["tests_failed", "accepted"]
    report = (ws / "SAGE_REPORT.md").read_text()
    assert "static analysis only" in report and "Lower assurance" in report
    assert "shell=True" not in (ws / "app.py").read_text()


def test_review_only_branch_when_no_patch_survives(tmp_path, monkeypatch):
    src = make_untested_repo(tmp_path / "src")

    async def fake_clone(url, dest, registry, token):
        subprocess.run(["git", "clone", "-q", str(src), str(dest)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/octo/untested.git"], cwd=dest, check=True)
        return "main"
    async def no_token():
        return None
    monkeypatch.setattr(pl, "clone", fake_clone)
    monkeypatch.setattr(pl, "github_token", no_token)
    inner = static_handler({"n": 0})

    def h(req):
        body = json.loads(req.content)
        if body["messages"][0]["content"].startswith("You are the Patcher"):
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"rationale": "x", "edits": [
                {"path": "app.py", "search": "does not exist anywhere", "replace": "y"}]})}}]})
        return inner(req)
    ws = tmp_path / "ws"
    ws.mkdir()
    reg = SecretRegistry()
    llm = GroqClient(SecretStr("gsk_" + "k" * 30), "m", reg, http=httpx.AsyncClient(transport=httpx.MockTransport(h)))
    settings = Settings(groq_key=SecretStr("x"), runs=1, max_iterations=2, dry_run=True, log=lambda m: None)

    async def go():
        async with McpBridge(ws) as bridge:
            p = Pipeline("https://github.com/octo/untested", "review it", ws, bridge, llm, settings, reg)
            return p, await p.run()
    p, res = asyncio.run(go())
    assert res.ok and not p.state.accepted and p.state.pr and p.state.pr.branch_name.startswith("sage/review-")
    files = subprocess.run(["git", "show", "--name-only", "--format=", "HEAD"], cwd=ws, capture_output=True, text=True).stdout.split()
    assert "SAGE_REPORT.md" in files and "app.py" not in files
    assert "No code was changed" in (ws / "SAGE_REPORT.md").read_text()


def test_optimization_mode_accepts_patch_when_program_output_unchanged(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("def total(xs):\n    t = 0\n    for x in xs:\n        t = t + x\n    return t\n\nprint(total([1, 2, 3]))\n")
    run = lambda *a: subprocess.run(a, cwd=src, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "remote", "add", "origin", "https://github.com/octo/opt.git")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")

    async def fake_clone(url, dest, registry, token):
        subprocess.run(["git", "clone", "-q", str(src), str(dest)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/octo/opt.git"], cwd=dest, check=True)
        return "main"
    async def no_token():
        return None
    monkeypatch.setattr(pl, "clone", fake_clone)
    monkeypatch.setattr(pl, "github_token", no_token)
    state = {"n": 0}

    def h(req):
        body = json.loads(req.content)
        sp = body["messages"][0]["content"]
        msg = lambda c: httpx.Response(200, json={"choices": [{"message": {"content": c}}]})
        if sp.startswith("You are the Code Auditor"):
            return msg(json.dumps({"summary": "tiny script", "optimizations": ["use sum()"], "issues": []}))
        if sp.startswith("You are the Planner"):
            return msg("ok") if body.get("tools") else msg(json.dumps({"summary": "use sum", "hypotheses": [], "target_files": ["main.py"]}))
        if sp.startswith("You are the Patcher"):
            state["n"] += 1
            # attempt 1 changes the output (rejected by smoke compare); attempt 2 preserves it
            rep = "return sum(xs) + 1" if state["n"] == 1 else "return sum(xs)"
            return msg(json.dumps({"rationale": "use sum()", "edits": [{"path": "main.py", "search": "    t = 0\n    for x in xs:\n        t = t + x\n    return t", "replace": "    " + rep}]}))
        return msg(json.dumps({"approved": True, "risk": "low", "issues": [], "summary": "ok"}))
    ws = tmp_path / "ws"
    ws.mkdir()
    reg = SecretRegistry()
    llm = GroqClient(SecretStr("gsk_" + "k" * 30), "m", reg, http=httpx.AsyncClient(transport=httpx.MockTransport(h)))
    settings = Settings(groq_key=SecretStr("x"), runs=1, max_iterations=3, dry_run=True, log=lambda m: None)

    async def go():
        async with McpBridge(ws) as bridge:
            p = Pipeline("https://github.com/octo/opt", "optimize", ws, bridge, llm, settings, reg)
            return p, await p.run()
    p, res = asyncio.run(go())
    assert res.ok and p.state.accepted and p.state.smoke_verified
    assert [a.outcome for a in p.state.attempts] == ["tests_failed", "accepted"]
    assert "sum(xs)" in (ws / "main.py").read_text()
    assert "smoke-run" in (ws / "SAGE_REPORT.md").read_text()


def test_live_dashboard_serves_state():
    import urllib.request
    from types import SimpleNamespace
    from sage.live import LiveServer
    from sage.schemas import PipelineState

    pipe = SimpleNamespace(statuses={"clone": "succeeded", "scan": "running"}, sched=None, logs=["hi"], done=False,
                           state=PipelineState(repo_url="https://github.com/o/r", goal="g", workspace="/w"))
    srv = LiveServer(pipe, SimpleNamespace(model="m", calls=3))
    url = srv.start()
    try:
        data = json.loads(urllib.request.urlopen(url + "state").read())
        assert data["llm_calls"] == 3 and data["nodes"][1] == {"name": "scan", "status": "running"}
        assert b"S.A.G.E." in urllib.request.urlopen(url).read()
    finally:
        srv.stop()


def test_readme_only_repo_gets_review_only_branch_without_planning(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# docs only\n" * 20)
    run = lambda *a: subprocess.run(a, cwd=src, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "remote", "add", "origin", "https://github.com/octo/docs.git")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")

    async def fake_clone(url, dest, registry, token):
        subprocess.run(["git", "clone", "-q", str(src), str(dest)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/octo/docs.git"], cwd=dest, check=True)
        return "main"
    async def no_token():
        return None
    monkeypatch.setattr(pl, "clone", fake_clone)
    monkeypatch.setattr(pl, "github_token", no_token)
    prompts = []

    def h(req):
        sp = json.loads(req.content)["messages"][0]["content"]
        prompts.append(sp[:24])
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
            {"summary": "docs only", "strengths": [], "issues": [], "optimizations": []})}}]})
    ws = tmp_path / "ws"
    ws.mkdir()
    reg = SecretRegistry()
    llm = GroqClient(SecretStr("gsk_" + "k" * 30), "m", reg, http=httpx.AsyncClient(transport=httpx.MockTransport(h)))
    settings = Settings(groq_key=SecretStr("x"), runs=1, dry_run=True, log=lambda m: None)

    async def go():
        async with McpBridge(ws) as bridge:
            p = Pipeline("https://github.com/octo/docs", "optimize", ws, bridge, llm, settings, reg)
            return p, await p.run()
    p, res = asyncio.run(go())
    assert res.ok and not p.state.accepted and p.state.pr.branch_name.startswith("sage/review-")
    assert prompts == ["You are the Code Auditor"]  # no Planner / Patcher calls were wasted
