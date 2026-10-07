"""The S.A.G.E. DAG: wires MCP tools and Groq agents into verified, parallelised stages."""
import asyncio
import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from . import agents
from .bridge import McpBridge
from .dag import DagResult, DagScheduler, Node, NonRetryable
from .llm import GroqClient
from .schemas import (AttemptRecord, ChangeRecord, CommitPRInput, PipelineState, ReportInput, RunTestsOutput,
                      ScanCredentialsOutput, SideMetrics)
from .git_ops import clone, github_token, parse_repo_url
from .redact import SecretRegistry


@dataclass
class Settings:
    groq_key: SecretStr
    model: str | None = None
    runs: int = 3
    max_iterations: int = 3
    test_timeout: int = 600
    dry_run: bool = False
    per_file_chars: int = 8000
    direct_plan_max_files: int = 8
    log: callable = print  # type: ignore[assignment]


def vuln_counts(scan: ScanCredentialsOutput | None) -> dict[str, int]:
    return dict(Counter(v.severity.value for v in scan.vulnerabilities)) if scan else {}


def metrics(run: RunTestsOutput | None, scan: ScanCredentialsOutput | None) -> SideMetrics:
    last = run.runs[-1] if run and run.runs else None
    return SideMetrics(tests_passed=last.passed if last else 0, tests_failed=(last.failed + last.errors) if last else 0,
                       pass_rate=run.pass_rate if run else 0.0, flaky=bool(run and run.flaky),
                       vuln_counts=vuln_counts(scan))


def evaluate(baseline: RunTestsOutput, after: RunTestsOutput) -> tuple[bool, list[str]]:
    """Verification-first gate. Untested or failing patches never pass."""
    why: list[str] = []
    if not after.install_ok:
        why.append("dependency install failed after patch")
    if not after.tests_found:
        why.append("no tests executed")
    if not after.all_passed:
        why.append(f"tests did not pass on every run (pass rate {after.pass_rate:.0%})")
    base_n = max((r.collected for r in baseline.runs), default=0)
    after_n = min((r.collected for r in after.runs), default=0)
    if after_n < base_n:
        why.append(f"test count dropped from {base_n} to {after_n}")
    return (not why), why


WEIGHT = {"critical": 8, "high": 5, "medium": 3, "low": 1, "info": 0}


def evaluate_static(before: ScanCredentialsOutput, after: ScanCredentialsOutput,
                    compiled: RunTestsOutput) -> tuple[bool, list[str]]:
    """Fallback gate for repos without tests: compiles, no new findings, weighted score strictly lower."""
    why: list[str] = []
    if not compiled.all_passed:
        why.append("compileall failed")
    score = lambda s: sum(WEIGHT[v.severity.value] for v in s.vulnerabilities)  # noqa: E731
    if score(after) >= score(before):
        why.append(f"finding score did not drop ({score(before)} -> {score(after)})")
    cb = Counter((v.rule_id, v.file) for v in before.vulnerabilities)
    ca = Counter((v.rule_id, v.file) for v in after.vulnerabilities)
    new = [k for k, n in ca.items() if n > cb.get(k, 0)]
    if new:
        why.append("new findings introduced: " + ", ".join(f"{r}@{f}" for r, f in new[:5]))
    return (not why), why


def smoke_sig(r: RunTestsOutput | None):  # type: ignore[no-untyped-def]
    if not r or not r.runs:
        return None
    s = r.runs[0]
    return (s.exit_code, s.timed_out, hashlib.sha256(r.log_tail.encode()).hexdigest())


def _score(s: ScanCredentialsOutput) -> int:
    return sum(WEIGHT[v.severity.value] for v in s.vulnerabilities)


def _needs_credential(v) -> bool:  # type: ignore[no-untyped-def]
    return v.sensitive and (v.required or v.confidence >= 0.6)


class Pipeline:
    def __init__(self, repo_url: str, goal: str, workspace: Path, bridge: McpBridge, llm: GroqClient,
                 settings: Settings, registry: SecretRegistry) -> None:
        self.s = settings
        self.bridge, self.llm, self.registry = bridge, llm, registry
        self.state = PipelineState(repo_url=repo_url, goal=goal, workspace=str(workspace))
        self.ws = workspace
        self.logs: list[str] = []
        self.statuses: dict[str, str] = {}
        self.sched: DagScheduler | None = None
        self.model: str = ""
        self.done = False

    async def _llm(self, label: str, coro):  # type: ignore[no-untyped-def]
        self.log(f"  {label}: asking {self.llm.model} ...")
        t0 = time.monotonic()
        result = await coro
        self.log(f"  {label}: done in {time.monotonic() - t0:.0f}s")
        return result

    def log(self, msg: str) -> None:
        self.logs.append(f"{time.strftime('%H:%M:%S')}  {msg}")
        del self.logs[:-400]
        self.s.log(msg)

    # ── nodes ─────────────────────────────────────────────
    async def n_clone(self) -> None:
        parse_repo_url(self.state.repo_url)
        token = await github_token()
        if token:
            self.registry.add(token)
        self.state.default_branch = await clone(self.state.repo_url, self.ws, self.registry, token)

    async def n_scan(self) -> None:
        self.state.scan = await self.bridge.scan()
        sc = self.state.scan
        self.log(f"  scan: {sc.files_scanned} files, {len(sc.env_vars)} env vars, "
                 f"{len(sc.clients)} clients, {len(sc.vulnerabilities)} findings")

    async def n_analyze(self) -> None:
        self.state.analytics = a = await self.bridge.analyze()
        self.log(f"  analytics: {a.files} files, {a.total_loc:,} LOC, {a.python_functions} functions, "
                 f"avg complexity {a.avg_complexity}, tests: {'yes' if a.has_tests else 'none'}")

    async def n_review(self) -> None:
        a, sc = self.state.analytics, self.state.scan
        assert a and sc
        paths = [h.file for h in a.hotspots] + [f.file for f in a.largest_files]
        files: dict[str, str] = {}
        for p in dict.fromkeys(paths):
            if len(files) >= 3:
                break
            try:
                files[p] = (await self.bridge.read_file(p, start_line=1, end_line=800, max_chars=5000)).content
            except Exception:  # noqa: BLE001
                continue
        atxt = (f"{a.files} files, {a.total_loc} LOC {a.loc_by_language}; functions={a.python_functions}; "
                f"avg_complexity={a.avg_complexity}; tests={a.test_files}; todos={a.todo_count}; "
                f"hotspots=" + "; ".join(f"{h.file}:{h.line} {h.name} cx={h.complexity}" for h in a.hotspots[:5]))
        ftxt = "\n".join(f"[{v.severity.value}] {v.rule_id} {v.file}:{v.line} {v.title}"
                         for v in sc.vulnerabilities[:25]) or "none"
        self.state.code_review = await self._llm("Code review", agents.run_code_review(
            self.llm, self.state.goal, atxt, ftxt, files))
        self.log(f"  code review: {len(self.state.code_review.issues)} issues, "
                 f"{len(self.state.code_review.optimizations)} optimization ideas")

    async def n_install(self) -> None:
        out = await self.bridge.run_tests(label="install", install_only=True, timeout_s=900)
        if not out.install_ok:
            raise NonRetryable("dependency install failed:\n" + out.log_tail[-1200:])

    async def n_credentials(self) -> None:
        assert self.state.scan
        wanted = [v for v in self.state.scan.env_vars if _needs_credential(v)][:15]
        for v in wanted:
            src = v.sources[0]
            res = await self.bridge.request_credential(v.name, f"Referenced at {src.file}:{src.line}")
            self.state.credentials[v.name] = res.status
            if res.status == "cancelled":
                self.log("  credential prompt cancelled — continuing without further prompts")
                break

    async def n_baseline(self) -> None:
        out = await self.bridge.run_tests(label="baseline", runs=self.s.runs, timeout_s=self.s.test_timeout)
        self.state.baseline = out
        if not out.install_ok:
            raise NonRetryable("dependency install failed:\n" + out.log_tail[-1200:])
        if not out.tests_found:
            self.state.verification = "static"
            self.log("  no tests found → static verification mode")
            sc = self.state.scan
            if sc and _score(sc) == 0:
                self.log("  no findings to fix → optimization mode: accepted only if program output is unchanged")
            self.state.smoke_baseline = sm = await self.bridge.run_tests(label="smoke-baseline", mode="smoke",
                                                                          timeout_s=20)
            self.state.before_output = sm.log_tail if sm.runs else None
            self.log(f"  entrypoint smoke run: " + ("no entrypoint found" if not sm.runs else
                     f"exit {sm.runs[0].exit_code}{' (timed out)' if sm.runs[0].timed_out else ''}"))
            return
        self.state.smoke_baseline = sm = await self.bridge.run_tests(label="smoke-baseline", mode="smoke", timeout_s=20)
        if sm.runs:
            self.state.before_output = sm.log_tail
            self.log(f"  program run (before): exit {sm.runs[0].exit_code}")
        m = metrics(out, None)
        self.log(f"  baseline: {m.tests_passed} passed, {m.tests_failed} failed, "
                 f"pass-rate {out.pass_rate:.0%}{' (flaky)' if out.flaky else ''}")

    def _brief(self) -> str:
        sc, bl = self.state.scan, self.state.baseline
        assert sc and bl
        vulns = "\n".join(f"- [{v.severity.value}] {v.rule_id} {v.file}:{v.line} {v.title}"
                          for v in sc.vulnerabilities[:25]) or "- none"
        if self.state.verification == "static":
            opt = ""
            if _score(sc) == 0 and self.state.code_review:
                opt = ("\nNO FINDINGS EXIST: propose small, behaviour-preserving improvements (robustness, clarity, "
                       "performance) taken from these review notes; program output must stay identical:\n- "
                       + "\n- ".join(self.state.code_review.optimizations[:6]
                                      + [i.detail for i in self.state.code_review.issues[:4]]) + "\n")
            return ("NO TEST SUITE EXISTS. Make small, behaviour-preserving changes only; verification is a compile "
                    "check plus finding score (or identical program output when there are no findings).\n" + opt + "\n"
                    f"STATIC FINDINGS:\n{vulns}\n\nENV VARS: {', '.join(v.name for v in sc.env_vars[:25])}")
        last = bl.runs[-1]
        return (f"BASELINE: passed={last.passed} failed={last.failed} errors={last.errors}, "
                f"pass_rate={bl.pass_rate:.0%}, flaky={bl.flaky}\nTEST LOG TAIL:\n{bl.log_tail[-2500:]}\n\n"
                f"STATIC FINDINGS:\n{vulns}\n\nENV VARS: {', '.join(v.name for v in sc.env_vars[:25])}")

    def _no_python(self) -> bool:
        a = self.state.analytics
        return bool(a and a.loc_by_language.get("Python", 0) == 0)

    async def n_plan(self) -> None:
        if self._no_python():
            self.log("  no Python source in this repository: S.A.G.E. patches Python only -> review-only report")
            return
        tool_defs = self.bridge.llm_tools(agents.PLANNER_TOOLS)
        files = await self.bridge.list_files("**/*.py", 150)
        brief = self._brief() + "\n\nPYTHON FILES:\n" + "\n".join(files.files)
        if self.state.code_review:
            brief += "\n\nCODE REVIEW SUMMARY: " + self.state.code_review.summary[:800]
        if len(files.files) <= self.s.direct_plan_max_files:
            contents: dict[str, str] = {}
            for p in files.files:
                try:
                    contents[p] = (await self.bridge.read_file(p, start_line=1, end_line=400, max_chars=3000)).content
                except Exception:  # noqa: BLE001
                    continue
            self.state.plan = await self._llm("Planner", agents.run_planner_direct(
                self.llm, self.state.goal, brief, contents))
        else:
            self.state.plan = await self._llm("Planner", agents.run_planner(
                self.llm, tool_defs, self.bridge.call_as_text, self.state.goal, brief))
        self.log(f"  plan ({self.state.plan.risk} risk): {self.state.plan.summary[:140]}")

    async def n_patch_loop(self) -> None:
        st = self.state
        if not st.plan:
            return
        assert st.baseline
        feedback: str | None = None
        for i in range(1, self.s.max_iterations + 1):
            self.log(f"  iteration {i}/{self.s.max_iterations}")
            files: dict[str, str] = {}
            for path in st.plan.target_files[:4]:
                try:
                    r = await self.bridge.read_file(path, start_line=1, end_line=3000, max_chars=self.s.per_file_chars)
                    files[path] = r.content
                except Exception as e:  # noqa: BLE001 — planner may name a missing file
                    files[path] = f"(unreadable: {str(e)[:120]})"
            proposal = await self._llm("Patcher", agents.run_patcher(
                self.llm, st.goal, st.plan, files, feedback, self.s.per_file_chars))
            applied = await self.bridge.apply_patches(proposal.edits)
            if not applied.applied:
                feedback = "Edits were rejected:\n" + "\n".join(applied.errors)
                st.attempts.append(AttemptRecord(iteration=i, outcome="apply_failed", detail=feedback[:500]))
                continue
            verdict = await self._llm("Reviewer", agents.run_reviewer(self.llm, st.goal, st.plan, proposal, applied.diff))
            if not verdict.approved:
                await self.bridge.revert()
                feedback = "Reviewer rejected: " + "; ".join(verdict.issues or [verdict.summary])
                st.attempts.append(AttemptRecord(iteration=i, outcome="review_rejected", detail=feedback[:500],
                                                 files=applied.files_changed))
                continue
            if st.verification == "static":
                after = await self.bridge.run_tests(label=f"compile-{i}", mode="compile", timeout_s=300)
                after_scan = await self.bridge.scan()
                ok, why = evaluate_static(st.scan, after_scan, after)
                if not ok and _score(st.scan) == 0 and after.all_passed and _score(after_scan) == 0:
                    sm = await self.bridge.run_tests(label=f"smoke-{i}", mode="smoke", timeout_s=20)
                    if smoke_sig(st.smoke_baseline) and smoke_sig(sm) == smoke_sig(st.smoke_baseline):
                        ok, st.smoke_verified = True, True
                        self.log("  program output identical before/after (smoke run)")
                    else:
                        why.append("smoke run unavailable or output changed")
                after.log_tail = after.log_tail or "; ".join(why)
            else:
                after = await self.bridge.run_tests(label=f"patched-{i}", runs=self.s.runs, timeout_s=self.s.test_timeout)
                ok, why = evaluate(st.baseline, after)
            if not ok:
                await self.bridge.revert()
                feedback = f"Verification failed: {'; '.join(why)}\nLOG TAIL:\n{after.log_tail[-2500:]}"
                st.attempts.append(AttemptRecord(iteration=i, outcome="tests_failed", detail="; ".join(why),
                                                 files=applied.files_changed))
                continue
            st.accepted, st.accepted_proposal, st.final_run = True, proposal, after
            st.changed_files = applied.files_changed
            st.attempts.append(AttemptRecord(iteration=i, outcome="accepted", detail=verdict.summary[:300],
                                             files=applied.files_changed))
            st.after_scan = await self.bridge.scan()
            if st.smoke_baseline and st.smoke_baseline.runs:
                fin = await self.bridge.run_tests(label="smoke-final", mode="smoke", timeout_s=20)
                st.after_output = fin.log_tail
                self.log(f"  program run (after): exit {fin.runs[0].exit_code if fin.runs else '?'}")
            self.log(f"  ✓ patch accepted and verified ({', '.join(applied.files_changed)})")
            self.review_notes = [verdict.summary, *verdict.issues]
            return
        self.log("  ✗ no patch survived verification — repository left unchanged")

    review_notes: list[str] = []

    async def n_report(self) -> None:
        st = self.state
        if not st.scan:
            raise NonRetryable("scan did not complete; nothing to report")
        prop = st.accepted_proposal
        rep = ReportInput(
            title=f"S.A.G.E.: {st.goal[:90]}", repo=st.repo_url, goal=st.goal,
            summary=(prop.rationale if prop else (st.code_review.summary if st.code_review else
                                                  (st.plan.summary if st.plan else "No plan produced.")))
            + ("" if st.accepted else "\n\nNo code was changed. This branch contains the review and analytics "
                                     "report only" + (" (no patch passed verification)." if st.plan else ".")),
            findings=st.scan.vulnerabilities[:100],
            changes=[ChangeRecord(file=f, summary=(prop.rationale if prop else "")[:200]) for f in st.changed_files],
            review_notes=[n for n in self.review_notes if n],
            before=metrics(st.baseline, st.scan), after=metrics(st.final_run, st.after_scan) if st.accepted else None,
            accepted=st.accepted, verification=("smoke" if st.smoke_verified else st.verification), analytics=st.analytics, code_review=st.code_review,
            before_output=st.before_output, after_output=st.after_output,
            attempts=[f"iteration {a.iteration}: {a.outcome} — {a.detail}" for a in st.attempts])
        st.report_path = (await self.bridge.report(rep)).path
        self.log(f"  report written: {st.report_path}")

    async def n_publish(self) -> None:
        st = self.state
        if not st.report_path:
            return
        slug = "".join(c if c.isalnum() else "-" for c in st.goal.lower())[:40].strip("-") or "fix"
        kind = "fix" if st.accepted else "review"
        how = "the repository test suite" if st.verification == "tests" else "static analysis (no tests)"
        msg = (f"S.A.G.E.: {st.goal[:100]}\n\nVerified by {how}. See {st.report_path}." if st.accepted else
               f"S.A.G.E. code review report: {st.goal[:80]}\n\nReport only; no code changed. See {st.report_path}.")
        out = await self.bridge.publish(CommitPRInput(
            branch_suffix=f"{kind}-{slug}", commit_message=msg,
            pr_title=(f"S.A.G.E.: {st.goal[:100]}" if st.accepted else f"S.A.G.E. review report: {st.goal[:80]}"),
            report_path=st.report_path, files=[st.report_path, *st.changed_files],
            draft=True, push=not self.s.dry_run))
        st.pr = out
        if not out.success:
            raise NonRetryable(out.error or "publish failed")
        self.log(f"  branch {out.branch_name} " + (f"→ {out.pr_url}" if out.pr_url else "(committed locally, --dry-run)"))

    # ── graph ─────────────────────────────────────────────
    def build(self) -> DagScheduler:
        def ev(name: str, status, err) -> None:  # type: ignore[no-untyped-def]
            self.statuses[name] = status.value
            icon = {"running": "▶", "succeeded": "✓", "failed": "✗", "skipped": "–"}.get(status.value, "?")
            self.log(f"[{icon}] {name}" + (f": {err.splitlines()[0][:160]}" if err else ""))

        nodes = [
            Node("clone", self.n_clone, retries=0, timeout=900),
            Node("scan", self.n_scan, ("clone",), timeout=300),
            Node("analyze", self.n_analyze, ("clone",), timeout=300),
            Node("review", self.n_review, ("scan", "analyze"), retries=1, timeout=600),
            Node("install", self.n_install, ("clone",), timeout=1000),
            Node("credentials", self.n_credentials, ("scan",), timeout=900),
            Node("baseline", self.n_baseline, ("install", "credentials"), timeout=self.s.test_timeout * self.s.runs + 900),
            Node("plan", self.n_plan, ("baseline", "scan", "review"), retries=1, timeout=600,
                 tolerate=frozenset({"review"})),
            Node("patch_loop", self.n_patch_loop, ("plan",), timeout=3 * 3600),
            Node("report", self.n_report, ("patch_loop", "review", "baseline"), timeout=120,
                 tolerate=frozenset({"patch_loop", "review", "baseline"})),
            Node("publish", self.n_publish, ("report",), timeout=900),
        ]
        self.statuses = {n.name: "pending" for n in nodes}
        self.sched = DagScheduler(nodes, max_concurrency=4, on_event=ev)
        return self.sched

    async def run(self) -> DagResult:
        return await self.build().run()
