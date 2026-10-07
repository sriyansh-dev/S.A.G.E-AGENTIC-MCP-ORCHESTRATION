"""Fish-shell venv bootstrap and pytest execution (CachyOS / Arch).

All variable data (paths, args) goes through the environment or $argv — never interpolated into
fish source — so nothing from the repo can inject shell code.
"""
import asyncio
import hashlib
import os
import re
import shutil
import signal
import time
from pathlib import Path

from .schemas import TestRunStats

REQ_FILES = ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "requirements-test.txt",
             "test-requirements.txt")
DEP_FILES = REQ_FILES + ("pyproject.toml", "setup.py", "setup.cfg")
_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed)")


class RunnerError(RuntimeError):
    pass


def require_fish() -> str:
    fish = shutil.which("fish")
    if not fish:
        raise RunnerError("fish not found. Install it: sudo pacman -S --needed fish")
    return fish


def build_install_script(ws: Path) -> str:
    pip = "pip install --quiet --disable-pip-version-check"
    lines = ["cd $SAGE_WS; or exit 2",
             "if not test -x .venv/bin/python",
             "  python -m venv .venv; or exit 11",
             "end",
             "source .venv/bin/activate.fish; or exit 12"]
    for req in REQ_FILES:
        if (ws / req).is_file():
            lines.append(f"{pip} -r {req}; or exit 14")
    if (ws / "pyproject.toml").is_file() or (ws / "setup.py").is_file():
        lines.append(f"{pip} -e '.[test,dev,tests]'; or echo '[sage] editable install failed; continuing' >&2")
    lines.append(f"python -c 'import pytest' 2>/dev/null; or {pip} pytest; or exit 16")
    return "\n".join(lines) + "\n"


TEST_SCRIPT = """cd $SAGE_WS; or exit 2
source .venv/bin/activate.fish; or exit 12
python -m pytest -q -p no:cacheprovider -rfE --color=no $argv
"""


COMPILE_SCRIPT = r"""cd $SAGE_WS; or exit 2
source .venv/bin/activate.fish; or exit 12
python -m compileall -q -x '/(\.venv|\.sage|node_modules|\.git)/' .
"""


async def run_compile_once(ws: Path, env: dict[str, str], timeout: float) -> tuple[TestRunStats, str]:
    t0 = time.monotonic()
    code, out, timed_out = await run_fish(COMPILE_SCRIPT, ws, env, timeout)
    return TestRunStats(exit_code=code, passed=0, failed=0, errors=0, skipped=0,
                        duration_s=round(time.monotonic() - t0, 2), timed_out=timed_out), out


SMOKE_SCRIPT = """cd $SAGE_WS; or exit 2
source .venv/bin/activate.fish; or exit 12
cd (dirname $argv[1]); or exit 3
python (basename $argv[1])
"""
_ENTRY_NAMES = ("main.py", "app.py", "run.py", "cli.py", "__main__.py", "server.py", "start.py")


def find_entrypoint(ws: Path) -> str | None:
    """Shallowest .py file with a __main__ guard (preferring conventional names), up to 3 levels deep."""
    from .scanner import SKIP_DIRS
    cands: list[tuple[int, int, str]] = []
    for p in sorted(ws.rglob("*.py")):
        parts = p.relative_to(ws).parts
        if (len(parts) > 3 or SKIP_DIRS.intersection(parts) or "tests" in parts or p.name.startswith("test_")
                or p.name in {"setup.py", "conftest.py"} or p.is_symlink()):
            continue
        try:
            has_main = "__main__" in p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if has_main:
            pri = _ENTRY_NAMES.index(p.name) if p.name in _ENTRY_NAMES else 99
            cands.append((len(parts), pri, "/".join(parts)))
    if cands:
        return min(cands)[2]
    for n in _ENTRY_NAMES:  # scripts without a __main__ guard still run top-level code
        if (ws / n).is_file():
            return n
    return None


async def run_smoke_once(ws: Path, env: dict[str, str], entry: str, timeout: float) -> tuple[TestRunStats, str]:
    t0 = time.monotonic()
    code, out, timed_out = await run_fish(SMOKE_SCRIPT, ws, env, timeout, (entry,))
    return TestRunStats(exit_code=code, passed=0, failed=0, errors=0, skipped=0,
                        duration_s=round(time.monotonic() - t0, 2), timed_out=timed_out), out


def deps_fingerprint(ws: Path) -> str:
    h = hashlib.sha256()
    for f in DEP_FILES:
        p = ws / f
        if p.is_file():
            h.update(f.encode())
            h.update(p.read_bytes())
    return h.hexdigest()


async def run_fish(script: str, ws: Path, env: dict[str, str], timeout: float,
                   args: tuple[str, ...] = ()) -> tuple[int, str, bool]:
    fish = require_fish()
    full_env = {**env, "SAGE_WS": str(ws), "CI": "true", "PYTHONUNBUFFERED": "1", "NO_COLOR": "1",
                "PYTHONDONTWRITEBYTECODE": "1"}
    full_env.pop("VIRTUAL_ENV", None)
    proc = await asyncio.create_subprocess_exec(
        fish, "--no-config", "-c", script, *args, cwd=str(ws), env=full_env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, start_new_session=True)
    buf = bytearray()

    async def drain() -> None:
        assert proc.stdout
        while chunk := await proc.stdout.read(65536):
            buf.extend(chunk)
            if len(buf) > 2_000_000:
                del buf[: len(buf) - 1_000_000]
        await proc.wait()

    timed_out = False
    try:
        await asyncio.wait_for(drain(), timeout)
    except asyncio.TimeoutError:
        timed_out = True
    finally:
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
    return (proc.returncode if proc.returncode is not None else -9), buf.decode("utf-8", "replace"), timed_out


def parse_pytest(output: str, exit_code: int, duration: float, timed_out: bool) -> TestRunStats:
    counts = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for line in reversed(output.strip().splitlines()[-8:]):
        if re.search(r"\bin [\d.]+s\b", line) or "no tests ran" in line:
            for n, word in _COUNT.findall(line):
                key = "error" if word.startswith("error") else word
                if key in counts:
                    counts[key] = int(n)
            break
    return TestRunStats(exit_code=exit_code, passed=counts["passed"], failed=counts["failed"],
                        errors=counts["error"], skipped=counts["skipped"], duration_s=round(duration, 2),
                        timed_out=timed_out)


async def ensure_install(ws: Path, env: dict[str, str], timeout: float) -> tuple[bool, str]:
    marker = ws / ".sage" / "install.sha"
    fp = deps_fingerprint(ws)
    if (ws / ".venv" / "bin" / "python").exists() and marker.exists() and marker.read_text() == fp:
        return True, ""
    code, out, timed_out = await run_fish(build_install_script(ws), ws, env, timeout)
    if code == 0 and not timed_out:
        marker.parent.mkdir(exist_ok=True)
        marker.write_text(fp)
        return True, out
    return False, out + ("\n[sage] install timed out" if timed_out else f"\n[sage] install exit {code}")


async def run_pytest_once(ws: Path, env: dict[str, str], timeout: float) -> tuple[TestRunStats, str]:
    t0 = time.monotonic()
    code, out, timed_out = await run_fish(TEST_SCRIPT, ws, env, timeout)
    return parse_pytest(out, code, time.monotonic() - t0, timed_out), out
