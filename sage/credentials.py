"""Credential vault (memory only) + native OS modal prompts. Values never leave this process."""
import asyncio
import getpass
import os
import shutil

from .redact import SecretRegistry
from .schemas import CredentialStatus


class CredentialVault:
    def __init__(self, registry: SecretRegistry) -> None:
        self._values: dict[str, str] = {}
        self._registry = registry

    def set(self, name: str, value: str) -> None:
        self._values[name] = value
        self._registry.add(value)

    def has(self, name: str) -> bool:
        return name in self._values

    def names(self) -> list[str]:
        return sorted(self._values)

    def env(self) -> dict[str, str]:
        """For subprocess environments and the ignored .env file only."""
        return dict(self._values)


async def _run(cmd: list[str]) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL, stdin=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await proc.communicate()
    except asyncio.CancelledError:
        proc.kill()
        raise
    return proc.returncode or 0, out.decode("utf-8", "replace").rstrip("\n")


def _gui_available() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


async def _kdialog(name: str, purpose: str) -> tuple[CredentialStatus, str | None]:
    text = f"S.A.G.E. needs {name} for live testing.\n{purpose}".strip()
    rc, _ = await _run(["kdialog", "--title", "S.A.G.E. credential", "--yesnocancel", text,
                        "--yes-label", "Provide", "--no-label", "Skip", "--cancel-label", "Cancel"])
    if rc == 2:
        return "cancelled", None
    if rc != 0:
        return "skipped", None
    rc, out = await _run(["kdialog", "--title", f"S.A.G.E.: {name}", "--password", f"Paste value for {name}:"])
    if rc != 0:
        return "cancelled", None
    return ("provided", out) if out else ("skipped", None)


async def _zenity(name: str, purpose: str) -> tuple[CredentialStatus, str | None]:
    text = f"S.A.G.E. needs {name} for live testing. {purpose}".strip()
    rc, out = await _run(["zenity", "--question", "--title", "S.A.G.E. credential", "--text", text,
                          "--ok-label", "Provide", "--cancel-label", "Cancel", "--extra-button", "Skip"])
    if rc != 0:
        return ("skipped", None) if out.strip() == "Skip" else ("cancelled", None)
    rc, out = await _run(["zenity", "--password", "--title", f"S.A.G.E.: {name}"])
    if rc != 0:
        return "cancelled", None
    return ("provided", out) if out else ("skipped", None)


async def _tty(name: str, purpose: str) -> tuple[CredentialStatus, str | None]:
    # The MCP stdio pipe owns stdin/stdout, so only /dev/tty is safe.
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        os.close(fd)
    except OSError:
        return "cancelled", None
    prompt = f"[S.A.G.E.] {name} ({purpose or 'live testing'}) — paste value, Enter to skip: "
    try:
        val = await asyncio.to_thread(getpass.getpass, prompt)
    except (EOFError, KeyboardInterrupt):
        return "cancelled", None
    return ("provided", val) if val else ("skipped", None)


async def prompt_credential(name: str, purpose: str, timeout: float = 120.0) -> tuple[CredentialStatus, str | None]:
    try:
        return await asyncio.wait_for(_prompt(name, purpose), timeout)
    except asyncio.TimeoutError:
        return "skipped", None  # nobody answered: never block the pipeline


async def _prompt(name: str, purpose: str) -> tuple[CredentialStatus, str | None]:
    kde = "KDE" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
    order = ["kdialog", "zenity"] if kde else ["zenity", "kdialog"]
    if _gui_available():
        for tool in order:
            if shutil.which(tool):
                return await (_kdialog if tool == "kdialog" else _zenity)(name, purpose)
    return await _tty(name, purpose)
