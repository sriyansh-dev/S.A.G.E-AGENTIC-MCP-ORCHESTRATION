"""MCP stdio server exposing the S.A.G.E. local tools. Run: python -m sage.mcp_server"""
import logging
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .schemas import (AnalyticsOutput, AnalyzeCodebaseInput, ApplyPatchesInput, ApplyPatchesOutput, CommitPRInput, CommitPROutput, ListRepoFilesInput,
                      ListRepoFilesOutput, ReadRepoFileInput, ReadRepoFileOutput, ReportInput, ReportOutput,
                      RequestCredentialInput, RequestCredentialOutput, RevertPatchesOutput, RunTestsInput,
                      RunTestsOutput, ScanCredentialsInput, ScanCredentialsOutput)
from .tools import Toolbox

logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="[sage-mcp] %(message)s")
for _n in ("mcp", "httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)
mcp = FastMCP("sage-local-bridge")
_tb: Toolbox | None = None


def tb() -> Toolbox:
    global _tb
    if _tb is None:
        ws = os.environ.get("SAGE_WORKSPACE")
        if not ws or not Path(ws).is_dir():
            raise RuntimeError("SAGE_WORKSPACE is not set to an existing directory")
        _tb = Toolbox(Path(ws))
    return _tb


@mcp.tool()
async def scan_codebase_credentials(params: ScanCredentialsInput) -> ScanCredentialsOutput:
    """Static scan (Python AST + regex) for expected env vars, API clients and vulnerabilities. Never returns values."""
    return await tb().scan_codebase_credentials(params)


@mcp.tool()
async def analyze_codebase(params: AnalyzeCodebaseInput) -> AnalyticsOutput:
    """Size, languages, Python complexity hotspots, TODO count and test presence."""
    return await tb().analyze_codebase(params)


@mcp.tool()
async def request_user_credential(params: RequestCredentialInput) -> RequestCredentialOutput:
    """Ask the human, via a native OS modal, for one credential. Returns status only."""
    return await tb().request_user_credential(params)


@mcp.tool()
async def run_tests_and_verify(params: RunTestsInput) -> RunTestsOutput:
    """Create a venv (fish), install dependencies and run the test suite `runs` times."""
    return await tb().run_tests_and_verify(params)


@mcp.tool()
async def commit_and_open_pr(params: CommitPRInput) -> CommitPROutput:
    """Create a new sage/* branch, commit verified files, push (forking if needed) and open a PR."""
    return await tb().commit_and_open_pr(params)


@mcp.tool()
async def generate_detailed_report(params: ReportInput) -> ReportOutput:
    """Write SAGE_REPORT.md (also used as the PR description)."""
    return await tb().generate_detailed_report(params)


@mcp.tool()
async def list_repo_files(params: ListRepoFilesInput) -> ListRepoFilesOutput:
    """List workspace files matching a glob (read-only)."""
    return await tb().list_repo_files(params)


@mcp.tool()
async def read_repo_file(params: ReadRepoFileInput) -> ReadRepoFileOutput:
    """Read a line range of a workspace file (secrets masked)."""
    return await tb().read_repo_file(params)


@mcp.tool()
async def apply_patches(params: ApplyPatchesInput) -> ApplyPatchesOutput:
    """Atomically apply exact-match search/replace edits; rejects syntax errors."""
    return await tb().apply_patches(params)


@mcp.tool()
async def revert_patches() -> RevertPatchesOutput:
    """Restore every file touched by apply_patches."""
    return await tb().revert_patches()


if __name__ == "__main__":
    mcp.run(transport="stdio")
