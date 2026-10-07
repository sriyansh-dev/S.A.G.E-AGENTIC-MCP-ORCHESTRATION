"""Strict Pydantic contracts for MCP tools, agents and DAG state.

Secret policy: no model in this file has a field that can carry a credential value.
Credential values live only in `CredentialVault` inside the MCP server process.
"""
import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
EnvName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]

_FORBIDDEN_PARTS = {".git", ".venv", ".sage", "node_modules"}


def _check_rel_path(v: str) -> str:
    if not v or len(v) > 512 or "\x00" in v:
        raise ValueError("invalid path")
    if v.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", v):
        raise ValueError("path must be relative to the workspace")
    parts = v.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("path traversal is not allowed")
    if _FORBIDDEN_PARTS.intersection(parts) or parts[-1] == ".env" or parts[-1].startswith(".env."):
        if not parts[-1].endswith((".example", ".sample", ".template")):
            raise ValueError("path is protected")
    return v


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ───────────────────────── scan ─────────────────────────
class SourceRef(Strict):
    file: str
    line: int
    via: str


class EnvVarFinding(Strict):
    name: EnvName
    sensitive: bool
    required: bool
    confidence: Confidence
    sources: list[SourceRef]


class ClientFinding(Strict):
    client: str
    file: str
    line: int
    env_hints: list[str]


class VulnFinding(Strict):
    rule_id: str
    severity: Severity
    file: str
    line: int
    title: str
    detail: str
    confidence: Confidence


class ScanCredentialsInput(Strict):
    max_files: int = Field(5000, ge=1, le=50000)


class ScanCredentialsOutput(Strict):
    files_scanned: int
    env_vars: list[EnvVarFinding]
    clients: list[ClientFinding]
    vulnerabilities: list[VulnFinding]


# ───────────────────────── credentials ─────────────────────────
CredentialStatus = Literal["provided", "skipped", "cancelled"]


class RequestCredentialInput(Strict):
    name: EnvName
    purpose: str = Field("", max_length=300)


class RequestCredentialOutput(Strict):
    name: str
    status: CredentialStatus


# ───────────────────────── read-only helpers ─────────────────────────
class ListRepoFilesInput(Strict):
    glob: str = Field("**/*", max_length=200)
    limit: int = Field(200, ge=1, le=1000)


class ListRepoFilesOutput(Strict):
    files: list[str]
    truncated: bool


class ReadRepoFileInput(Strict):
    path: str
    start_line: int = Field(1, ge=1)
    end_line: int = Field(400, ge=1)
    max_chars: int = Field(12000, ge=200, le=60000)

    @field_validator("path")
    @classmethod
    def _p(cls, v: str) -> str:
        return _check_rel_path(v)


class ReadRepoFileOutput(Strict):
    path: str
    start_line: int
    end_line: int
    total_lines: int
    content: str
    truncated: bool


# ───────────────────────── patches ─────────────────────────
class FileEdit(Strict):
    """Exact-match edit. `search` must match exactly once; empty `search` creates a new file."""

    path: str
    search: str = ""
    replace: str

    @field_validator("path")
    @classmethod
    def _p(cls, v: str) -> str:
        return _check_rel_path(v)


class ApplyPatchesInput(Strict):
    edits: list[FileEdit] = Field(min_length=1, max_length=20)


class ApplyPatchesOutput(Strict):
    applied: bool
    files_changed: list[str]
    diff: str
    errors: list[str]


class RevertPatchesOutput(Strict):
    reverted_files: list[str]


# ───────────────────────── verification ─────────────────────────
class RunTestsInput(Strict):
    label: str = Field("patched", pattern=r"^[a-z0-9-]{1,32}$")
    runs: int = Field(1, ge=1, le=10)
    timeout_s: int = Field(600, ge=5, le=3600)
    install_only: bool = False
    mode: Literal["tests", "compile", "smoke"] = "tests"


class TestRunStats(Strict):
    __test__ = False  # not a pytest class
    exit_code: int
    passed: int
    failed: int
    errors: int
    skipped: int
    duration_s: float
    timed_out: bool = False

    @property
    def collected(self) -> int:
        return self.passed + self.failed + self.errors + self.skipped


class RunTestsOutput(Strict):
    label: str
    install_ok: bool
    tests_found: bool
    all_passed: bool
    exit_status: int
    pass_rate: Confidence
    flaky: bool
    runs: list[TestRunStats]
    log_tail: str


class CommitPRInput(Strict):
    branch_suffix: str = Field(pattern=r"^[A-Za-z0-9._-]{1,60}$")
    commit_message: str = Field(min_length=1, max_length=2000)
    pr_title: str = Field(min_length=1, max_length=120)
    report_path: str
    files: list[str] = Field(min_length=1, max_length=50)
    draft: bool = True
    push: bool = True

    @field_validator("report_path")
    @classmethod
    def _rp(cls, v: str) -> str:
        return _check_rel_path(v)

    @field_validator("files")
    @classmethod
    def _f(cls, v: list[str]) -> list[str]:
        return [_check_rel_path(x) for x in v]


class CommitPROutput(Strict):
    success: bool
    pr_url: str | None = None
    branch_name: str | None = None
    commit_sha: str | None = None
    pushed_to: str | None = None
    error: str | None = None


# ───────────────────────── analytics + code review ─────────────────────────
class FunctionMetric(Strict):
    file: str
    name: str
    line: int
    complexity: int
    length: int


class FileStat(Strict):
    file: str
    loc: int


class AnalyzeCodebaseInput(Strict):
    max_files: int = Field(5000, ge=1, le=50000)


class AnalyticsOutput(Strict):
    files: int
    total_loc: int
    loc_by_language: dict[str, int]
    python_functions: int
    avg_complexity: float
    hotspots: list[FunctionMetric]
    largest_files: list[FileStat]
    todo_count: int
    test_files: int
    has_tests: bool
    dependency_files: list[str]


class ReviewIssue(Strict):
    severity: Literal["high", "medium", "low"]
    file: str = ""
    detail: str
    suggestion: str = ""


class CodeReview(Strict):
    summary: str
    strengths: list[str] = []
    issues: list[ReviewIssue] = []
    optimizations: list[str] = []


# ───────────────────────── report ─────────────────────────
class ChangeRecord(Strict):
    file: str
    summary: str


class SideMetrics(Strict):
    tests_passed: int
    tests_failed: int
    pass_rate: Confidence
    flaky: bool
    vuln_counts: dict[str, int]


class ReportInput(Strict):
    title: str = Field(max_length=200)
    repo: str
    goal: str = Field(max_length=2000)
    summary: str = Field(max_length=6000)
    findings: list[VulnFinding]
    changes: list[ChangeRecord]
    review_notes: list[str]
    before: SideMetrics
    after: SideMetrics | None
    accepted: bool
    attempts: list[str]
    verification: Literal["tests", "static", "smoke"] = "tests"
    analytics: AnalyticsOutput | None = None
    code_review: CodeReview | None = None
    before_output: str | None = None
    after_output: str | None = None


class ReportOutput(Strict):
    path: str
    size_bytes: int


# ───────────────────────── agents ─────────────────────────
class Hypothesis(Strict):
    title: str
    evidence: str
    files: list[str] = []


class Plan(Strict):
    summary: str
    hypotheses: list[Hypothesis] = Field(max_length=8)
    target_files: list[str] = Field(min_length=1, max_length=6)
    risk: Literal["low", "medium", "high"] = "medium"

    @field_validator("target_files")
    @classmethod
    def _t(cls, v: list[str]) -> list[str]:
        return [_check_rel_path(x) for x in v]


class PatchProposal(Strict):
    rationale: str
    addresses: list[str] = []
    edits: list[FileEdit] = Field(min_length=1, max_length=20)


class ReviewVerdict(Strict):
    approved: bool
    risk: Literal["low", "medium", "high"] = "medium"
    issues: list[str] = []
    summary: str = ""


# ───────────────────────── DAG state (secret-free) ─────────────────────────
class AttemptRecord(Strict):
    iteration: int
    outcome: Literal["apply_failed", "review_rejected", "tests_failed", "accepted"]
    detail: str
    files: list[str] = []


class PipelineState(Strict):
    repo_url: str
    goal: str
    workspace: str
    default_branch: str | None = None
    scan: ScanCredentialsOutput | None = None
    credentials: dict[str, CredentialStatus] = {}
    baseline: RunTestsOutput | None = None
    plan: Plan | None = None
    attempts: list[AttemptRecord] = []
    accepted: bool = False
    accepted_proposal: PatchProposal | None = None
    changed_files: list[str] = []
    verification: Literal["tests", "static"] = "tests"
    smoke_baseline: RunTestsOutput | None = None
    smoke_verified: bool = False
    before_output: str | None = None
    after_output: str | None = None
    final_run: RunTestsOutput | None = None
    analytics: AnalyticsOutput | None = None
    code_review: CodeReview | None = None
    after_scan: ScanCredentialsOutput | None = None
    report_path: str | None = None
    pr: CommitPROutput | None = None
