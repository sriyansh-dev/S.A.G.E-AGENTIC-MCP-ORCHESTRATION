"""Git + GitHub plumbing. Tokens travel only via GIT_CONFIG_* env vars / Authorization headers."""
import asyncio
import base64
import os
import re
import shutil
from pathlib import Path

import httpx

from .redact import SecretRegistry
from .retry import RetryableError, with_backoff

_REPO_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class GitError(RuntimeError):
    pass


def parse_repo_url(url: str) -> tuple[str, str]:
    m = _REPO_RE.match(url.strip())
    if not m or m.group(1) in {".", ".."} or m.group(2) in {".", ".."}:
        raise GitError("Only github.com repositories are supported (https://github.com/<owner>/<repo>).")
    return m.group(1), m.group(2)


def https_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}.git"


async def github_token() -> str | None:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if shutil.which("gh"):
        proc = await asyncio.create_subprocess_exec("gh", "auth", "token", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL,
                                                    stdin=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        tok = out.decode().strip()
        if proc.returncode == 0 and tok:
            return tok
    return None


def auth_env(token: str | None) -> dict[str, str]:
    env = {"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    if token:
        b64 = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                    "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {b64}"})
    return env


async def git(args: list[str], cwd: Path, registry: SecretRegistry, *, extra_env: dict[str, str] | None = None,
              timeout: float = 300, check: bool = True) -> tuple[int, str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", **(extra_env or {})}
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=str(cwd), env=env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise GitError(f"git {args[0]} timed out after {timeout:.0f}s")
    text = out.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise GitError(f"git {args[0]} failed ({proc.returncode}): {registry.redact(text)[-1500:]}")
    return proc.returncode or 0, text


async def clone(url: str, dest: Path, registry: SecretRegistry, token: str | None) -> str:
    owner, repo = parse_repo_url(url)
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise GitError(f"workspace {dest} is not empty")

    async def once() -> None:
        try:
            await git(["clone", "--depth", "50", "--", https_url(owner, repo), "."], dest, registry,
                      extra_env=auth_env(token), timeout=600)
        except GitError as e:
            if any(s in str(e) for s in ("Could not resolve", "unable to access", "timed out", "RPC failed")):
                raise RetryableError(str(e))
            raise

    await with_backoff(once, attempts=4, base=2.0)
    _, branch = await git(["rev-parse", "--abbrev-ref", "HEAD"], dest, registry)
    return branch.strip()


class GitHubAPI:
    def __init__(self, token: str, registry: SecretRegistry, http: httpx.AsyncClient | None = None) -> None:
        self._h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sage-bridge"}
        self._http = http or httpx.AsyncClient(base_url="https://api.github.com", timeout=30)
        self._reg = registry

    async def aclose(self) -> None:
        await self._http.aclose()

    async def req(self, method: str, path: str, **kw) -> httpx.Response:
        async def once() -> httpx.Response:
            try:
                r = await self._http.request(method, path, headers=self._h, **kw)
            except httpx.TransportError as e:
                raise RetryableError(type(e).__name__)
            if r.status_code in (500, 502, 503, 504):
                raise RetryableError(f"HTTP {r.status_code}")
            if r.status_code in (403, 429) and ("rate limit" in r.text.lower() or r.headers.get("retry-after")):
                ra = r.headers.get("retry-after")
                raise RetryableError("rate limited", float(ra) if ra and ra.isdigit() else 20.0)
            return r
        return await with_backoff(once, attempts=5, base=1.5)

    async def login(self) -> str:
        r = await self.req("GET", "/user")
        if r.status_code != 200:
            raise GitError(f"GitHub auth failed (HTTP {r.status_code}). Run `gh auth login`.")
        return r.json()["login"]

    async def can_push(self, owner: str, repo: str) -> bool:
        r = await self.req("GET", f"/repos/{owner}/{repo}")
        if r.status_code != 200:
            raise GitError(f"cannot access {owner}/{repo} (HTTP {r.status_code})")
        return bool(r.json().get("permissions", {}).get("push"))

    async def ensure_fork(self, owner: str, repo: str, me: str) -> tuple[str, str]:
        r = await self.req("POST", f"/repos/{owner}/{repo}/forks", json={})
        if r.status_code not in (200, 201, 202):
            raise GitError(f"fork failed (HTTP {r.status_code})")
        fo, fr = r.json()["owner"]["login"], r.json()["name"]
        for i in range(12):
            g = await self.req("GET", f"/repos/{fo}/{fr}")
            if g.status_code == 200:
                return fo, fr
            await asyncio.sleep(min(10, 1.5 * (i + 1)))
        raise GitError("fork was not ready in time")

    async def open_pr(self, owner: str, repo: str, *, head: str, base: str, title: str, body: str,
                      draft: bool) -> str:
        r = await self.req("POST", f"/repos/{owner}/{repo}/pulls", json={
            "title": title, "head": head, "base": base, "body": body[:60000], "draft": draft,
            "maintainer_can_modify": True})
        if r.status_code == 201:
            return r.json()["html_url"]
        raise GitError(f"PR creation failed (HTTP {r.status_code}): {self._reg.redact(r.text)[:400]}")


async def github_login_name(token: str) -> str | None:
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            r = await c.get("https://api.github.com/user", headers={"Authorization": f"Bearer {token}",
                                                                   "User-Agent": "sage-bridge"})
        except httpx.TransportError:
            return None
    return r.json().get("login") if r.status_code == 200 else None


async def ensure_github_auth(log) -> str | None:  # type: ignore[no-untyped-def]
    """Return the GitHub login, running `gh auth login --web` (browser, no pasting) if needed."""
    tok = await github_token()
    if not tok and shutil.which("gh"):
        log("GitHub: not logged in — starting browser login (copy the one-time code shown, approve in browser)")
        proc = await asyncio.create_subprocess_exec("gh", "auth", "login", "--web", "-h", "github.com", "-p", "https",
                                                    "-s", "repo")
        await proc.wait()
        tok = await github_token()
    if not tok:
        log("GitHub: no credentials (install github-cli and run `gh auth login`, or export GITHUB_TOKEN)")
        return None
    name = await github_login_name(tok)
    log(f"GitHub: logged in as {name}" if name else "GitHub: token present but could not be verified")
    return name
