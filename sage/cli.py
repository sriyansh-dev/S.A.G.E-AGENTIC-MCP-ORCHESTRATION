"""CLI entry: python -m sage"""
import argparse
import asyncio
import getpass
import os
import re
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

from pydantic import SecretStr

from .bridge import McpBridge
from .git_ops import GitError, ensure_github_auth, parse_repo_url
from .live import LiveServer
from .llm import GroqClient
from .pipeline import Pipeline, Settings
from .redact import SecretRegistry
from .runner import RunnerError, require_fish


def _ask(prompt: str, secret: bool = False) -> str:
    try:
        return (getpass.getpass(prompt) if secret else input(prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(130)


async def amain(args: argparse.Namespace) -> int:
    require_fish()
    if args.groq_key:
        key, src = args.groq_key, "--groq-key"
    elif os.environ.get("GROQ_API_KEY"):
        key, src = os.environ["GROQ_API_KEY"], "GROQ_API_KEY env var"
    else:
        key, src = _ask("Groq API key (hidden): ", secret=True), "typed prompt"
    if not key:
        print("A Groq API key is required.", file=sys.stderr)
        return 2
    repo = args.repo or _ask("GitHub repository URL: ")
    goal = args.goal or _ask("Goal (e.g. 'flaky in CI, find out why and fix what is safe'): ")
    owner, name = parse_repo_url(repo)
    log = lambda m: print(m, flush=True)  # noqa: E731
    if not args.dry_run:
        if not await ensure_github_auth(log):
            print("Cannot push without GitHub credentials. Re-run with --dry-run to work locally.", file=sys.stderr)
            return 2
    registry = SecretRegistry()
    ws = Path(args.workspace_root).expanduser() / f"{owner}-{name}-{time.strftime('%Y%m%d-%H%M%S')}"
    ws.mkdir(parents=True, exist_ok=False)
    settings = Settings(groq_key=SecretStr(key), model=args.model, runs=args.runs, max_iterations=args.max_iterations,
                        test_timeout=args.test_timeout, dry_run=args.dry_run, log=log)
    llm = GroqClient(settings.groq_key, args.model or "llama-3.3-70b-versatile", registry)
    llm.log = log
    print(f"workspace (cloned code lives here): {ws}")
    try:
        model = await llm.resolve_model(args.model)
        print(f"Groq: key from {src} (…{key[-4:]}), model {model}")
    except Exception as e:  # noqa: BLE001
        await llm.aclose()
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        async with McpBridge(ws) as bridge:
            pipe = Pipeline(repo, goal, ws, bridge, llm, settings, registry)
            llm.log = pipe.log
            live = None
            if not args.no_ui:
                try:
                    live = LiveServer(pipe, llm, args.port)
                    url = live.start()
                    print(f"LIVE DASHBOARD: {url}   (VS Code: Ctrl+Shift+P → 'Simple Browser: Show' → paste this URL)")
                    webbrowser.open(url)
                except OSError as e:
                    print(f"(live dashboard unavailable: {e})")
            try:
                result = await pipe.run()
            finally:
                pipe.done = True
                if live:
                    await asyncio.sleep(2.5)  # let the browser fetch the final state
                    live.stop()
    finally:
        await llm.aclose()
    st = pipe.state
    print(f"\nGroq API calls made: {llm.calls} (model {llm.model})")
    print("── result ──")
    for n, r in result.nodes.items():
        print(f"  {n:<12} {r.status.value:<10} {r.duration_s:>7.1f}s" + (f"  {r.error.splitlines()[0][:100]}" if r.error else ""))
    if st.pr and st.pr.success:
        print(f"\nBranch: {st.pr.branch_name}   PR: {st.pr.pr_url or '(local commit only; use without --dry-run to push)'}")
    if st.report_path and not args.no_open and shutil.which("code"):
        subprocess.Popen(["code", "-n", str(ws)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Opened the updated workspace in a new VS Code window.")
    if st.report_path:
        print(f"Report: {ws / st.report_path}\nUpdated code: cd {ws}   (git diff {st.default_branch}..HEAD)")
    return 0 if result.ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="sage", description="S.A.G.E. local execution bridge")
    ap.add_argument("--repo")
    ap.add_argument("--goal")
    ap.add_argument("--groq-key", help="prefer GROQ_API_KEY or the hidden prompt (argv is visible in ps)")
    ap.add_argument("--model", default=None, help="default: auto-pick the best model your Groq key can use")
    ap.add_argument("--runs", type=int, default=3, choices=range(1, 11), metavar="1-10",
                    help="test runs per verification (flake detection)")
    ap.add_argument("--max-iterations", type=int, default=3)
    ap.add_argument("--test-timeout", type=int, default=600)
    ap.add_argument("--workspace-root", default="~/.cache/sage/workspaces")
    ap.add_argument("--no-open", action="store_true", help="do not open the updated workspace in VS Code")
    ap.add_argument("--no-ui", action="store_true", help="do not start the live dashboard")
    ap.add_argument("--port", type=int, default=0, help="dashboard port (default: random free port)")
    ap.add_argument("--dry-run", action="store_true", help="verify and commit locally; do not push or open a PR")
    args = ap.parse_args()
    try:
        return asyncio.run(amain(args))
    except (GitError, RunnerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
