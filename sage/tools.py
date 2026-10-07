"""S.A.G.E. tool implementations. The MCP server is a thin wrapper around `Toolbox`."""
import asyncio
import difflib
import os
import re
import time
from pathlib import Path

from . import git_ops, runner
from .credentials import CredentialVault, prompt_credential
from .redact import SecretRegistry
from .analytics import analyze_workspace
from .scanner import scan_workspace
from .schemas import (AnalyticsOutput, AnalyzeCodebaseInput, ApplyPatchesInput, ApplyPatchesOutput, CommitPRInput, CommitPROutput, ListRepoFilesInput,
                      ListRepoFilesOutput, ReadRepoFileInput, ReadRepoFileOutput, ReportInput, ReportOutput,
                      RequestCredentialInput, RequestCredentialOutput, RevertPatchesOutput, RunTestsInput,
                      RunTestsOutput, ScanCredentialsInput, ScanCredentialsOutput, Severity, TestRunStats)

PROTECTED_PREFIXES = (".git/", ".venv/", ".sage/", "node_modules/")
GITIGNORE_ENTRIES = [".env", ".venv/", ".sage/", "__pycache__/"]
MAX_EDIT_FILE = 500_000


class ToolError(RuntimeError):
    pass


def safe_join(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if not p.is_relative_to(root.resolve()):
        raise ToolError("path escapes workspace")
    rp = p.relative_to(root.resolve()).as_posix() + ("/" if p.is_dir() else "")
    if rp.startswith(PROTECTED_PREFIXES) or p.name == ".env":
        raise ToolError("protected path")
    return p


def _locate(text: str, search: str) -> tuple[int, int] | str:
    n = text.count(search)
    if n == 1:
        i = text.index(search)
        return i, i + len(search)
    if n > 1:
        return f"search text is ambiguous ({n} matches); include more context"
    lines = text.splitlines(keepends=True)
    want = [s.rstrip() for s in search.splitlines()]
    if not want:
        return "search text not found"
    hits = [i for i in range(len(lines) - len(want) + 1)
            if all(lines[i + j].rstrip() == want[j] for j in range(len(want)))]
    if len(hits) != 1:
        return "search text not found" if not hits else f"search text is ambiguous ({len(hits)} matches)"
    start = sum(len(x) for x in lines[: hits[0]])
    end = start + sum(len(x) for x in lines[hits[0]: hits[0] + len(want)])
    if not search.endswith("\n") and text[start:end].endswith("\n"):
        end -= 1
    return start, end


class Toolbox:
    def __init__(self, workspace: Path, registry: SecretRegistry | None = None) -> None:
        self.ws = workspace.resolve()
        self.registry = registry or SecretRegistry()
        self.vault = CredentialVault(self.registry)
        self._snapshots: dict[str, str | None] = {}
        self._lock = asyncio.Lock()
        self._token: str | None = None

    # ── 1. scan ──────────────────────────────────────────────
    async def scan_codebase_credentials(self, p: ScanCredentialsInput) -> ScanCredentialsOutput:
        return await asyncio.to_thread(scan_workspace, self.ws, self.registry, p.max_files)

    async def analyze_codebase(self, p: AnalyzeCodebaseInput) -> AnalyticsOutput:
        return await asyncio.to_thread(analyze_workspace, self.ws, p.max_files)

    # ── 2. credentials ───────────────────────────────────────
    async def request_user_credential(self, p: RequestCredentialInput) -> RequestCredentialOutput:
        if self.vault.has(p.name):
            return RequestCredentialOutput(name=p.name, status="provided")
        status, value = await prompt_credential(p.name, p.purpose)
        if status == "provided" and value:
            self.vault.set(p.name, value)
            await asyncio.to_thread(self._write_dotenv)
        return RequestCredentialOutput(name=p.name, status=status)

    async def _ensure_gitignore(self) -> bool:
        gi = self.ws / ".gitignore"
        existing = gi.read_text() if gi.exists() else ""
        have = {ln.strip() for ln in existing.splitlines()}
        missing = [e for e in GITIGNORE_ENTRIES if e not in have and e.rstrip("/") not in have]
        if missing:
            sep = "" if existing.endswith("\n") or not existing else "\n"
            gi.write_text(existing + sep + "# added by S.A.G.E.\n" + "\n".join(missing) + "\n")
        return bool(missing)

    def _write_dotenv(self) -> None:
        gi = self.ws / ".gitignore"
        existing = gi.read_text() if gi.exists() else ""
        if ".env" not in {ln.strip() for ln in existing.splitlines()}:
            gi.write_text(existing + ("" if existing.endswith("\n") or not existing else "\n")
                          + "# added by S.A.G.E.\n" + "\n".join(GITIGNORE_ENTRIES) + "\n")
        lines = []
        for k, v in self.vault.env().items():
            esc = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'{k}="{esc}"')
        tmp = self.ws / ".env.sage-tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, self.ws / ".env")

    # ── read-only helpers ────────────────────────────────────
    async def list_repo_files(self, p: ListRepoFilesInput) -> ListRepoFilesOutput:
        def work() -> ListRepoFilesOutput:
            out: list[str] = []
            for f in sorted(self.ws.glob(p.glob)):
                if f.is_file() and not f.is_symlink():
                    rel = f.relative_to(self.ws).as_posix()
                    if not rel.startswith(PROTECTED_PREFIXES) and f.name != ".env" and "__pycache__" not in rel:
                        out.append(rel)
                if len(out) > p.limit:
                    break
            return ListRepoFilesOutput(files=out[: p.limit], truncated=len(out) > p.limit)
        return await asyncio.to_thread(work)

    async def read_repo_file(self, p: ReadRepoFileInput) -> ReadRepoFileOutput:
        f = safe_join(self.ws, p.path)
        if not f.is_file() or f.stat().st_size > 2_000_000:
            raise ToolError("not a readable file")
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        chunk = "".join(lines[p.start_line - 1: p.end_line])
        truncated = len(chunk) > p.max_chars
        return ReadRepoFileOutput(path=p.path, start_line=p.start_line, end_line=min(p.end_line, len(lines)),
                                  total_lines=len(lines), content=self.registry.mask(chunk[: p.max_chars]),
                                  truncated=truncated or p.end_line < len(lines))

    # ── patches ──────────────────────────────────────────────
    async def apply_patches(self, p: ApplyPatchesInput) -> ApplyPatchesOutput:
        async with self._lock:
            return await asyncio.to_thread(self._apply, p)

    def _apply(self, p: ApplyPatchesInput) -> ApplyPatchesOutput:
        working: dict[str, str | None] = {}
        originals: dict[str, str | None] = {}
        errors: list[str] = []
        for i, e in enumerate(p.edits, 1):
            try:
                f = safe_join(self.ws, e.path)
            except ToolError as ex:
                errors.append(f"edit {i} ({e.path}): {ex}")
                continue
            if self.registry.has_placeholder(e.replace):
                errors.append(f"edit {i}: `replace` contains a secret placeholder; read the value from the environment")
                continue
            if e.path not in working:
                if f.exists():
                    if f.stat().st_size > MAX_EDIT_FILE:
                        errors.append(f"edit {i}: {e.path} is too large to edit")
                        continue
                    originals[e.path] = working[e.path] = f.read_text(encoding="utf-8")
                else:
                    originals[e.path], working[e.path] = None, None
            cur = working[e.path]
            if e.search == "":
                if cur is not None:
                    errors.append(f"edit {i}: {e.path} already exists; give a `search` block")
                    continue
                working[e.path] = e.replace
                continue
            if cur is None:
                errors.append(f"edit {i}: {e.path} does not exist")
                continue
            loc = _locate(cur, self.registry.unmask(e.search))
            if isinstance(loc, str):
                errors.append(f"edit {i} ({e.path}): {loc}")
                continue
            working[e.path] = cur[: loc[0]] + e.replace + cur[loc[1]:]
        for path, new in working.items():
            if new is not None and path.endswith(".py"):
                try:
                    compile(new, path, "exec")
                except SyntaxError as ex:
                    errors.append(f"{path}: result has a syntax error at line {ex.lineno}: {ex.msg}")
        if errors:
            return ApplyPatchesOutput(applied=False, files_changed=[], diff="", errors=errors)
        diff_parts = []
        for path, new in working.items():
            old = originals[path]
            if new == old:
                continue
            self._snapshots.setdefault(path, old)
            target = safe_join(self.ws, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(new or "", encoding="utf-8")
            diff_parts.extend(difflib.unified_diff((old or "").splitlines(keepends=True),
                                                   (new or "").splitlines(keepends=True),
                                                   f"a/{path}", f"b/{path}"))
        changed = sorted(self._snapshots)
        return ApplyPatchesOutput(applied=True, files_changed=changed,
                                  diff=self.registry.redact("".join(diff_parts))[:30000], errors=[])

    async def revert_patches(self) -> RevertPatchesOutput:
        async with self._lock:
            done = []
            for path, old in self._snapshots.items():
                f = safe_join(self.ws, path)
                if old is None:
                    f.unlink(missing_ok=True)
                else:
                    f.write_text(old, encoding="utf-8")
                done.append(path)
            self._snapshots.clear()
            return RevertPatchesOutput(reverted_files=sorted(done))

    # ── 3. verify ────────────────────────────────────────────
    async def run_tests_and_verify(self, p: RunTestsInput) -> RunTestsOutput:
        async with self._lock:
            env = {**{k: v for k, v in os.environ.items()}, **self.vault.env()}
            ok, install_log = await runner.ensure_install(self.ws, env, timeout=900)
            if not ok:
                return RunTestsOutput(label=p.label, install_ok=False, tests_found=False, all_passed=False,
                                      exit_status=1, pass_rate=0.0, flaky=False, runs=[],
                                      log_tail=self._tail(install_log))
            if p.install_only:
                return RunTestsOutput(label=p.label, install_ok=True, tests_found=False, all_passed=False,
                                      exit_status=0, pass_rate=0.0, flaky=False, runs=[], log_tail="")
            if p.mode == "smoke":
                entry = runner.find_entrypoint(self.ws)
                if not entry:
                    return RunTestsOutput(label=p.label, install_ok=True, tests_found=False, all_passed=False,
                                          exit_status=3, pass_rate=0.0, flaky=False, runs=[],
                                          log_tail="no entrypoint found")
                stats, out = await runner.run_smoke_once(self.ws, env, entry, min(p.timeout_s, 60))
                ok = stats.exit_code == 0 and not stats.timed_out
                return RunTestsOutput(label=p.label, install_ok=True, tests_found=False, all_passed=ok,
                                      exit_status=stats.exit_code, pass_rate=1.0 if ok else 0.0, flaky=False,
                                      runs=[stats], log_tail=self._tail(f"[entry: {entry}]\n{out}"))
            if p.mode == "compile":
                stats, out = await runner.run_compile_once(self.ws, env, p.timeout_s)
                ok = stats.exit_code == 0 and not stats.timed_out
                return RunTestsOutput(label=p.label, install_ok=True, tests_found=False, all_passed=ok,
                                      exit_status=stats.exit_code, pass_rate=1.0 if ok else 0.0, flaky=False,
                                      runs=[stats], log_tail=self._tail(out))
            runs: list[TestRunStats] = []
            last_out = ""
            for _ in range(p.runs):
                stats, last_out = await runner.run_pytest_once(self.ws, env, p.timeout_s)
                runs.append(stats)
            passes = [r.exit_code == 0 and r.collected > 0 for r in runs]
            tests_found = any(r.collected > 0 for r in runs)
            worst = next((r.exit_code for r in runs if r.exit_code != 0), 0)
            return RunTestsOutput(
                label=p.label, install_ok=True, tests_found=tests_found, all_passed=tests_found and all(passes),
                exit_status=worst, pass_rate=round(sum(passes) / len(runs), 3),
                flaky=len(set(passes)) > 1 or len({(r.passed, r.failed, r.errors) for r in runs}) > 1,
                runs=runs, log_tail=self._tail(last_out))

    def _tail(self, text: str) -> str:
        return self.registry.redact("\n".join(text.splitlines()[-60:])[-6000:])

    # ── 4. commit + PR ───────────────────────────────────────
    async def commit_and_open_pr(self, p: CommitPRInput) -> CommitPROutput:
        reg = self.registry
        try:
            return await self._commit_and_open_pr(p)
        except (git_ops.GitError, ToolError) as e:
            return CommitPROutput(success=False, error=reg.redact(str(e))[:1500])
        except Exception as e:  # noqa: BLE001 — never crash the server on publish
            return CommitPROutput(success=False, error=reg.redact(f"{type(e).__name__}: {e}")[:500])

    async def _commit_and_open_pr(self, p: CommitPRInput) -> CommitPROutput:
        reg, ws, g = self.registry, self.ws, git_ops.git
        token = self._token or await git_ops.github_token()
        if p.push and not token:
            raise git_ops.GitError("No GitHub credentials. Run `gh auth login` or export GITHUB_TOKEN.")
        if token:
            self._token = token
            reg.add(token)
            reg.add(__import__("base64").b64encode(f"x-access-token:{token}".encode()).decode())
        _, base = await g(["rev-parse", "--abbrev-ref", "HEAD"], ws, reg)
        base = base.strip()
        _, remote = await g(["remote", "get-url", "origin"], ws, reg)
        owner, repo = git_ops.parse_repo_url(remote.strip())
        branch = f"sage/{p.branch_suffix}"
        rc, _ = await g(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], ws, reg, check=False)
        if rc == 0:
            branch += f"-{int(time.time())}"
        await g(["checkout", "-b", branch], ws, reg)
        await self._ensure_gitignore()
        paths = {x for x in [*p.files, p.report_path, ".gitignore"]}
        for rel in sorted(paths):
            safe_join(ws, rel)
            await g(["add", "-A", "--", rel], ws, reg)
        _, staged = await g(["diff", "--cached", "--name-only"], ws, reg)
        names = [n for n in staged.splitlines() if n]
        if not names:
            raise ToolError("nothing staged; no changes to commit")
        bad = [n for n in names if n.startswith(PROTECTED_PREFIXES) or Path(n).name == ".env"]
        if bad:
            await g(["reset", "-q"], ws, reg, check=False)
            raise ToolError(f"refusing to commit protected files: {', '.join(bad)}")
        _, patch = await g(["diff", "--cached", "-U0"], ws, reg)
        added = "\n".join(ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
        leaks = reg.leaks(added)
        if leaks:
            await g(["reset", "-q"], ws, reg, check=False)
            raise ToolError(f"aborted: staged additions contain {leaks} secret-like value(s); nothing was committed")
        ident = []
        for key, default in (("user.name", "S.A.G.E. Bot"), ("user.email", "sage-bot@users.noreply.github.com")):
            rc, val = await g(["config", key], ws, reg, check=False)
            if rc != 0 or not val.strip():
                ident += ["-c", f"{key}={default}"]
        await g([*ident, "commit", "-q", "-m", p.commit_message], ws, reg)
        _, sha = await g(["rev-parse", "HEAD"], ws, reg)
        sha = sha.strip()
        if not p.push:
            return CommitPROutput(success=True, branch_name=branch, commit_sha=sha, pushed_to=None)
        assert token
        api = git_ops.GitHubAPI(token, reg)
        try:
            me = await api.login()
            target_owner, target_repo = owner, repo
            if not await api.can_push(owner, repo):
                target_owner, target_repo = await api.ensure_fork(owner, repo, me)
            await g(["push", "--", git_ops.https_url(target_owner, target_repo), f"HEAD:refs/heads/{branch}"],
                    ws, reg, extra_env=git_ops.auth_env(token), timeout=600)
            head = branch if (target_owner, target_repo) == (owner, repo) else f"{target_owner}:{branch}"
            body = (ws / p.report_path).read_text(encoding="utf-8")
            url = await api.open_pr(owner, repo, head=head, base=base, title=p.pr_title, body=reg.redact(body),
                                    draft=p.draft)
        finally:
            await api.aclose()
        return CommitPROutput(success=True, pr_url=url, branch_name=branch, commit_sha=sha,
                              pushed_to=f"{target_owner}/{target_repo}")

    # ── 5. report ────────────────────────────────────────────
    async def generate_detailed_report(self, p: ReportInput) -> ReportOutput:
        md = self.registry.redact(render_report(p))
        out = self.ws / "SAGE_REPORT.md"
        await asyncio.to_thread(out.write_text, md, "utf-8")
        return ReportOutput(path="SAGE_REPORT.md", size_bytes=len(md.encode()))


def _fence(text: str | None) -> str:
    body = (text or "(no output)").replace("```", "~~~")[-2500:]
    return "```text\n" + body + "\n```"


def render_report(r: ReportInput) -> str:
    def esc(s: str) -> str:
        return re.sub(r"\s+", " ", s).replace("|", "\\|")

    b, a = r.before, r.after
    sev = [s.value for s in Severity]
    static = r.verification in ("static", "smoke")
    status = (("VERIFIED by program smoke-run (no test suite)" if r.verification == "smoke"
               else "VERIFIED by static analysis only (no test suite)") if static else "VERIFIED — patches accepted") \
        if r.accepted else "NO PATCH ACCEPTED"
    out = [f"# {r.title}", "",
           f"> Generated by **S.A.G.E.** (Secure Agentic Git Engine) for `{r.repo}`. Status: **{status}**.", ""]
    if static:
        how = ("they compile, add no findings, and the program's entrypoint produced the identical exit code and output "
               "before and after (smoke run)" if r.verification == "smoke" else
               "they compile, introduce no new findings and strictly reduce the weighted finding score")
        out += [f"> ⚠️ **Lower assurance:** this repository has no runnable tests. Changes were accepted only because "
                f"{how}. Behaviour beyond that was not tested — please review carefully.", ""]
    out += ["## Goal", "", r.goal, "", "## Summary", "", r.summary, "", "## Before / after", "",
            "| Metric | Before | After |", "|---|---|---|"]
    if not static:
        out += [f"| Tests passed | {b.tests_passed} | {a.tests_passed if a else '—'} |",
                f"| Tests failed | {b.tests_failed} | {a.tests_failed if a else '—'} |",
                f"| Suite pass rate | {b.pass_rate:.0%} | {f'{a.pass_rate:.0%}' if a else '—'} |",
                f"| Flaky across runs | {'yes' if b.flaky else 'no'} | {('yes' if a.flaky else 'no') if a else '—'} |"]
    for s in sev:
        if b.vuln_counts.get(s) or (a and a.vuln_counts.get(s)):
            out.append(f"| {s.capitalize()} findings | {b.vuln_counts.get(s, 0)} | {a.vuln_counts.get(s, 0) if a else '—'} |")
    an, cr = r.analytics, r.code_review
    if an:
        out += ["", "## Code analytics", "",
                f"- **{an.files} files, {an.total_loc:,} lines** — " + ", ".join(
                    f"{k} {v:,}" for k, v in sorted(an.loc_by_language.items(), key=lambda kv: -kv[1])[:6]),
                f"- Python functions: {an.python_functions}, average cyclomatic complexity: {an.avg_complexity}",
                f"- Tests: {'yes' if an.has_tests else '**none**'} ({an.test_files} test files); TODO/FIXME markers: {an.todo_count}",
                f"- Dependency manifests: {', '.join(f'`{d}`' for d in an.dependency_files) or 'none'}"]
        if an.hotspots:
            out += ["", "| Complexity hotspot | Complexity | Lines |", "|---|---|---|"]
            out += [f"| `{h.file}:{h.line}` `{h.name}()` | {h.complexity} | {h.length} |" for h in an.hotspots[:6]]
    if cr:
        out += ["", "## Code review", "", cr.summary]
        if cr.strengths:
            out += ["", "**Strengths**"] + [f"- {esc(x)}" for x in cr.strengths]
        if cr.issues:
            out += ["", "| Severity | Location | Issue | Suggestion |", "|---|---|---|---|"]
            out += [f"| {i.severity} | `{i.file}` | {esc(i.detail)} | {esc(i.suggestion)} |" for i in cr.issues[:25]]
        if cr.optimizations:
            out += ["", "**Optimization opportunities**"] + [f"- {esc(x)}" for x in cr.optimizations]
    if r.before_output or r.after_output:
        out += ["", "## Live program run", "", "**Before**", _fence(r.before_output)]
        if r.after_output:
            out += ["", "**After**", _fence(r.after_output)]
    out += ["", "## Findings detected", ""]
    if r.findings:
        out += ["| Severity | Rule | Location | Confidence | Note |", "|---|---|---|---|---|"]
        out += [f"| {f.severity.value} | `{f.rule_id}` | `{f.file}:{f.line}` | {f.confidence:.0%} | {esc(f.title)} |"
                for f in r.findings[:60]]
        if len(r.findings) > 60:
            out.append(f"\n_{len(r.findings) - 60} more omitted._")
    else:
        out.append("None.")
    out += ["", "## Changes", ""]
    out += [f"- `{c.file}` — {esc(c.summary)}" for c in r.changes] or ["No files were changed."]
    out += ["", "## Review notes", ""] + ([f"- {esc(n)}" for n in r.review_notes] or ["None."])
    out += ["", "## Attempt log", ""] + ([f"{i}. {esc(x)}" for i, x in enumerate(r.attempts, 1)] or ["None."])
    out += ["", "## Verification policy", "",
            ("A patch is accepted only if the project's test suite passes on every verification run, no test was "
             "removed, and the static review approved the diff. " if not static else
             "With no test suite, a patch is accepted only if every file compiles, no new findings appear, and either "
             "the weighted finding score strictly drops or (when there were no findings) the program's smoke-run "
             "output is identical before and after; the review must also approve the diff. ") +
            "Credentials supplied for live testing were held in "
            "memory, written only to a git-ignored `.env`, and never sent to the LLM.", ""]
    return "\n".join(out)
