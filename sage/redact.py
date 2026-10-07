"""Secret detection / redaction shared by every component that emits text."""
import re
import threading

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("groq-key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("openai-key", re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{16,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("uri-credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
]

_PLACEHOLDER = re.compile(r"\{\{SAGE_SECRET_(\d+)\}\}")


class SecretRegistry:
    """Thread-safe set of known secret values plus pattern-based detection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, int] = {}
        self._by_id: dict[int, str] = {}

    def add(self, value: str | None) -> None:
        if not value or len(value) < 4:
            return
        with self._lock:
            if value not in self._values:
                idx = len(self._values) + 1
                self._values[value] = idx
                self._by_id[idx] = value

    def _all_spans(self, text: str) -> list[tuple[int, int, str]]:
        spans: list[tuple[int, int, str]] = []
        with self._lock:
            known = sorted(self._values, key=len, reverse=True)
        for v in known:
            for m in re.finditer(re.escape(v), text):
                spans.append((m.start(), m.end(), v))
        for _, pat in SECRET_PATTERNS:
            for m in pat.finditer(text):
                spans.append((m.start(), m.end(), m.group(0)))
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        merged: list[tuple[int, int, str]] = []
        for s in spans:
            if merged and s[0] < merged[-1][1]:
                continue
            merged.append(s)
        return merged

    def redact(self, text: str) -> str:
        """Irreversible: for logs, errors, diffs shown anywhere."""
        out, last = [], 0
        for s, e, _ in self._all_spans(text):
            out.append(text[last:s])
            out.append("[REDACTED]")
            last = e
        out.append(text[last:])
        return "".join(out)

    def mask(self, text: str) -> str:
        """Reversible placeholders so an LLM can still anchor an edit on a secret-bearing line."""
        out, last = [], 0
        for s, e, v in self._all_spans(text):
            self.add(v)
            out.append(text[last:s])
            out.append("{{SAGE_SECRET_%d}}" % self._values[v])
            last = e
        out.append(text[last:])
        return "".join(out)

    def unmask(self, text: str) -> str:
        return _PLACEHOLDER.sub(lambda m: self._by_id.get(int(m.group(1)), m.group(0)), text)

    @staticmethod
    def has_placeholder(text: str) -> bool:
        return bool(_PLACEHOLDER.search(text))

    def leaks(self, text: str) -> int:
        """Number of secret occurrences in text (never returns the values)."""
        return len(self._all_spans(text))
