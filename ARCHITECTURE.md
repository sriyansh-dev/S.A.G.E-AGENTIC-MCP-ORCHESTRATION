# S.A.G.E. — Local Execution Bridge

## 1. System architecture (sequence)

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant CLI as CLI / Orchestrator
    participant DAG as asyncio DAG
    participant MCP as MCP server (stdio, local)
    participant G as Groq API
    participant GH as GitHub

    U->>CLI: Groq key (hidden), repo URL, goal
    CLI->>MCP: spawn (env WITHOUT Groq key)
    CLI->>DAG: run()
    DAG->>GH: clone (gh/GITHUB_TOKEN via env header)
    par parallel after clone
        DAG->>MCP: scan_codebase_credentials
        MCP-->>DAG: env var names, sources, confidence, findings (no values)
    and
        DAG->>MCP: run_tests_and_verify(install_only) [fish venv + pip]
    end
    loop each sensitive/required var
        DAG->>MCP: request_user_credential(name)
        MCP->>U: native modal (kdialog/zenity/tty)
        U-->>MCP: value (held in MCP memory + ignored .env)
        MCP-->>DAG: provided | skipped | cancelled
    end
    DAG->>MCP: run_tests_and_verify(baseline, runs=N)
    MCP-->>DAG: pass/fail counts, flaky flag, sanitized log tail
    DAG->>G: Planner (tool-calling: list_repo_files / read_repo_file / scan)
    G->>MCP: tool calls (via DAG relay, read-only allowlist)
    G-->>DAG: Plan (JSON, validated)
    loop up to max_iterations
        DAG->>G: Patcher(plan, files, feedback)
        G-->>DAG: PatchProposal (search/replace edits)
        DAG->>MCP: apply_patches (atomic, syntax-checked)
        DAG->>G: Reviewer(diff)
        alt rejected
            DAG->>MCP: revert_patches
        else approved
            DAG->>MCP: run_tests_and_verify(patched-i, runs=N)
            alt tests fail / test count drops
                DAG->>MCP: revert_patches (+ log tail fed back)
            else verified
                Note over DAG: accept, re-scan for after-metrics
            end
        end
    end
    DAG->>MCP: generate_detailed_report
    DAG->>MCP: commit_and_open_pr
    MCP->>MCP: secret scan of staged additions
    MCP->>GH: push sage/* branch (fork if no push access), open draft PR
    MCP-->>CLI: PR URL
```

DAG: `clone → {scan ∥ analyze ∥ install}`, `review` (scan+analyze), `credentials` (scan) → `baseline` (install+credentials) → `plan` → `patch_loop` → `report` → `publish`. See README for the diagram.
A failed node skips its dependents; independent branches keep running.

## 2. Secret-handling boundaries

| Secret | Lives in | Never reaches |
|---|---|---|
| Groq key | Orchestrator memory (`SecretStr`) | MCP server env, logs, state |
| Live-test credentials | MCP server memory + `0600 .env` (git-ignored) | Orchestrator, Groq, report, commits |
| GitHub token | MCP server memory; passed to git via `GIT_CONFIG_*` env | argv, logs |
| Secrets found in repo source | Registry → masked as `{{SAGE_SECRET_n}}` for the LLM | LLM prompts, diffs, PR body |

Note: repository *source* is sent to Groq; credentials you enter are not.

## 3. Edge cases

| Case | Behaviour |
|---|---|
| No tests / 0 collected | Falls back to **static verification**: compileall passes, no new findings, weighted finding score strictly drops; PR marked lower-assurance |
| Patch breaks syntax / search not unique | Whole edit set rejected atomically; error fed back |
| Patch deletes tests | Rejected (collected count must not drop) |
| Flaky suite | `runs` repeats; all must pass; flaky flag in report |
| Groq 429/5xx/timeout | Exponential backoff + jitter, honours `Retry-After` |
| Invalid LLM JSON | Up to 3 repair rounds with validation errors |
| No push access | Auto-fork, PR from fork |
| Secret in staged additions | Commit aborted, index reset |
| Test hangs | Process-group SIGKILL on timeout |
| Credential dialog cancelled | Remaining prompts skipped |
