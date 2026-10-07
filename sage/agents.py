"""Planner / Patcher / Reviewer agents (Groq). Planner may call read-only MCP tools."""
from collections.abc import Awaitable, Callable

from .llm import GroqClient
from .schemas import Plan, PatchProposal, ReviewVerdict

PLANNER_TOOLS = {"scan_codebase_credentials", "list_repo_files", "read_repo_file"}

PLANNER_SYS = """You are the Planner of S.A.G.E., an autonomous repository repair system.
Investigate with the read-only tools (list_repo_files, read_repo_file), then decide what is SAFE to fix for the user's goal.
Prefer minimal, verifiable changes. Never plan changes that need new secrets, delete tests, or alter CI credentials.
Secrets appear as {{SAGE_SECRET_n}} placeholders; never reproduce them.
When finished investigating, stop calling tools."""

PLAN_FORMAT = """Return ONLY a JSON object:
{"summary": str, "hypotheses": [{"title": str, "evidence": str, "files": [str]}],
 "target_files": [relative paths, 1-6, files you will edit], "risk": "low"|"medium"|"high"}"""

PATCHER_SYS = """You are the Patcher of S.A.G.E. You write minimal, correct patches as exact search/replace edits.
Rules: every `search` must be copied EXACTLY from the file content provided and be unique in that file (include enough
surrounding lines); keep indentation; do not rewrite whole files; do not delete or weaken tests; do not add secrets;
read configuration from os.environ instead of hardcoding. {{SAGE_SECRET_n}} placeholders may appear in `search` only.
Return ONLY JSON:
{"rationale": str, "addresses": [finding or hypothesis titles], "edits": [{"path": str, "search": str, "replace": str}]}
To create a new file use an empty `search`."""

REVIEWER_SYS = """You are the Reviewer of S.A.G.E. Check a unified diff for correctness, regressions, unsafe behaviour,
leaked secrets, removed/weakened tests and scope creep versus the goal. Be strict but fair: approve only if the diff is
minimal and clearly addresses the plan. Return ONLY JSON:
{"approved": bool, "risk": "low"|"medium"|"high", "issues": [str], "summary": str}"""


def _trim(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n // 2] + "\n…[truncated]…\n" + text[-n // 2:]


PLANNER_DIRECT_SYS = """You are the Planner of S.A.G.E., an autonomous repository repair system.
You are given the repository's files. Decide what is SAFE to fix for the user's goal. Prefer minimal, verifiable changes.
Never plan changes that need new secrets, delete tests, or alter CI credentials. {{SAGE_SECRET_n}} placeholders are masked secrets."""


async def run_planner_direct(llm: GroqClient, goal: str, brief: str, files: dict[str, str]) -> Plan:
    body = "\n\n".join(f"=== FILE: {p} ===\n{_trim(c, 3000)}" for p, c in files.items())
    return await llm.chat_model([
        {"role": "system", "content": PLANNER_DIRECT_SYS + "\n" + PLAN_FORMAT},
        {"role": "user", "content": f"GOAL: {goal}\n\n{brief}\n\n{body}"}], Plan)


async def run_planner(llm: GroqClient, tool_defs: list[dict], call_tool: Callable[[str, dict], Awaitable[str]],
                      goal: str, brief: str) -> Plan:
    msgs = [{"role": "system", "content": PLANNER_SYS},
            {"role": "user", "content": f"GOAL: {goal}\n\n{brief}"}]
    msgs = await llm.run_with_tools(msgs, tool_defs, call_tool, max_rounds=3)
    if msgs[-1]["role"] == "assistant" and not msgs[-1].get("tool_calls"):
        msgs.pop()  # discard free-text; ask for the structured plan
    msgs.append({"role": "user", "content": "Now produce the final plan.\n" + PLAN_FORMAT})
    # tool_calls in history require a tools param on some providers; flatten to plain text
    flat = []
    for m in msgs:
        if m["role"] == "tool":
            flat.append({"role": "user", "content": "[tool result] " + m["content"]})
        elif m["role"] == "assistant" and m.get("tool_calls"):
            names = ", ".join(c["function"]["name"] for c in m["tool_calls"])
            flat.append({"role": "assistant", "content": f"(called: {names})"})
        else:
            flat.append(m)
    return await llm.chat_model(flat, Plan)


async def run_patcher(llm: GroqClient, goal: str, plan: Plan, files: dict[str, str],
                      feedback: str | None, per_file_chars: int) -> PatchProposal:
    body = "\n\n".join(f"=== FILE: {p} ===\n{_trim(c, per_file_chars)}" for p, c in files.items())
    user = (f"GOAL: {goal}\nPLAN: {plan.summary}\nHYPOTHESES: "
            + "; ".join(f"{h.title} ({h.evidence[:160]})" for h in plan.hypotheses)
            + f"\n\n{body}")
    if feedback:
        user += f"\n\nPREVIOUS ATTEMPT FAILED — fix this:\n{_trim(feedback, 3500)}"
    return await llm.chat_model([{"role": "system", "content": PATCHER_SYS}, {"role": "user", "content": user}],
                                PatchProposal)


async def run_reviewer(llm: GroqClient, goal: str, plan: Plan, proposal: PatchProposal, diff: str) -> ReviewVerdict:
    user = (f"GOAL: {goal}\nPLAN: {plan.summary}\nPATCHER RATIONALE: {proposal.rationale}\n\nDIFF:\n{_trim(diff, 14000)}")
    return await llm.chat_model([{"role": "system", "content": REVIEWER_SYS}, {"role": "user", "content": user}],
                                ReviewVerdict)


AUDITOR_SYS = """You are the Code Auditor of S.A.G.E. Write an honest, specific code review of a repository from its analytics,
static findings and file excerpts. Cite real files. Do not invent problems you cannot see. Cover correctness risks, security,
error handling, structure/maintainability and performance. Return ONLY JSON:
{"summary": str (3-5 sentences), "strengths": [str], "issues": [{"severity": "high"|"medium"|"low", "file": str, "detail": str, "suggestion": str}],
 "optimizations": [str]}"""


async def run_code_review(llm: GroqClient, goal: str, analytics_text: str, findings_text: str,
                          files: dict[str, str]):
    from .schemas import CodeReview
    body = "\n\n".join(f"=== FILE: {p} ===\n{_trim(c, 5000)}" for p, c in files.items())
    user = f"GOAL: {goal}\n\nANALYTICS:\n{analytics_text}\n\nSTATIC FINDINGS:\n{findings_text}\n\n{body}"
    return await llm.chat_model([{"role": "system", "content": AUDITOR_SYS}, {"role": "user", "content": user}],
                                CodeReview)
