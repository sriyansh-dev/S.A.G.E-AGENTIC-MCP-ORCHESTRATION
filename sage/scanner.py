"""Static discovery of env vars, API-client signatures and vulnerabilities.

Python → `ast`; everything else → regex. Output never contains secret values.
"""
import ast
import os
import re
from pathlib import Path

from .redact import SECRET_PATTERNS, SecretRegistry
from .schemas import (ClientFinding, EnvVarFinding, ScanCredentialsOutput, Severity, SourceRef,
                      VulnFinding)

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", ".tox", ".mypy_cache",
                       ".pytest_cache", "__pycache__", "dist", "build", ".idea", ".vscode", ".sage",
                       "site-packages", ".next", "target", "vendor"})
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php", ".java",
                 ".kt", ".rs", ".sh", ".bash", ".fish"}
CONFIG_SUFFIXES = {".yml", ".yaml", ".toml", ".json", ".ini", ".cfg", ".tf", ".md", ".txt"}
SPECIAL_NAMES = {"Dockerfile", "docker-compose.yml", "Makefile"}
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
MAX_BYTES = 1_000_000
IGNORED_ENV = {"PATH", "HOME", "USER", "PWD", "SHELL", "LANG", "LC_ALL", "TERM", "TMPDIR", "TMP", "TEMP",
               "HOSTNAME", "PYTHONPATH", "VIRTUAL_ENV", "CI", "OLDPWD", "EDITOR", "DISPLAY"}
SENSITIVE_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASS(WORD|WD)?|DSN|CREDENTIAL|PRIVATE|AUTH|(^|_)(URL|URI)$|CONN(ECTION)?(_?STR(ING)?)?$)", re.I)
VALID_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
PLACEHOLDER_HINTS = ("example", "your", "xxxx", "1234567890", "placeholder", "dummy", "fake", "changeme",
                     "<", "test", "redacted")

# (label, env hints, confidence the hint is really needed)
CLIENTS_BY_TAIL: dict[str, tuple[str, list[str], float]] = {
    "OpenAI": ("OpenAI", ["OPENAI_API_KEY"], 0.7), "AsyncOpenAI": ("OpenAI", ["OPENAI_API_KEY"], 0.7),
    "Anthropic": ("Anthropic", ["ANTHROPIC_API_KEY"], 0.7), "AsyncAnthropic": ("Anthropic", ["ANTHROPIC_API_KEY"], 0.7),
    "Groq": ("Groq", ["GROQ_API_KEY"], 0.7), "AsyncGroq": ("Groq", ["GROQ_API_KEY"], 0.7),
    "TavilyClient": ("Tavily", ["TAVILY_API_KEY"], 0.6), "AsyncTavilyClient": ("Tavily", ["TAVILY_API_KEY"], 0.6),
    "MongoClient": ("MongoDB", ["MONGODB_URI"], 0.4), "AsyncIOMotorClient": ("MongoDB", ["MONGODB_URI"], 0.4),
    "SendGridAPIClient": ("SendGrid", ["SENDGRID_API_KEY"], 0.6), "Pinecone": ("Pinecone", ["PINECONE_API_KEY"], 0.6),
    "CohereClient": ("Cohere", ["COHERE_API_KEY"], 0.6),
}
CLIENTS_BY_DOTTED: dict[str, tuple[str, list[str], float]] = {
    "boto3.client": ("AWS", ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], 0.4),
    "boto3.resource": ("AWS", ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], 0.4),
    "psycopg2.connect": ("PostgreSQL", ["DATABASE_URL"], 0.4), "psycopg.connect": ("PostgreSQL", ["DATABASE_URL"], 0.4),
    "asyncpg.connect": ("PostgreSQL", ["DATABASE_URL"], 0.4), "asyncpg.create_pool": ("PostgreSQL", ["DATABASE_URL"], 0.4),
    "create_engine": ("SQLAlchemy", ["DATABASE_URL"], 0.4), "create_async_engine": ("SQLAlchemy", ["DATABASE_URL"], 0.4),
    "sqlalchemy.create_engine": ("SQLAlchemy", ["DATABASE_URL"], 0.4),
    "redis.Redis": ("Redis", ["REDIS_URL"], 0.4), "redis.from_url": ("Redis", ["REDIS_URL"], 0.4),
    "Redis.from_url": ("Redis", ["REDIS_URL"], 0.4), "genai.configure": ("Google GenAI", ["GOOGLE_API_KEY"], 0.6),
}
ENV_GET = {"os.environ.get", "environ.get", "os.getenv", "getenv"}
ENV_HELPERS = {"config", "env", "env.str", "env.int", "env.bool", "env.float", "env.get", "env.url"}
NODE_ENV_PATTERNS = [
    (re.compile(r"process\.env\.([A-Za-z_]\w*)"), "process.env"),
    (re.compile(r"process\.env\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]"), "process.env"),
    (re.compile(r"import\.meta\.env\.([A-Za-z_]\w*)"), "import.meta.env"),
    (re.compile(r"os\.(?:Getenv|LookupEnv)\(\s*\"([A-Za-z_]\w*)\"\s*\)"), "os.Getenv"),
    (re.compile(r"System\.getenv\(\s*\"([A-Za-z_]\w*)\"\s*\)"), "System.getenv"),
    (re.compile(r"\bENV\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]"), "ENV[]"),
    (re.compile(r"\bgetenv\(\s*['\"]([A-Za-z_]\w*)['\"]\s*\)"), "getenv()"),
    (re.compile(r"std::env::var\(\s*\"([A-Za-z_]\w*)\"\s*\)"), "std::env::var"),
]
PY_FALLBACK_PATTERNS = [
    (re.compile(r"os\.environ\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]"), "os.environ[]"),
    (re.compile(r"(?:os\.environ\.get|os\.getenv)\(\s*['\"]([A-Za-z_]\w*)['\"]"), "os.getenv"),
]
SHELL_VAR = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(:?[-?+][^}]*)?\}")
GHA_SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_]\w*)\s*\}\}")
DOTENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
HARDCODED_ASSIGN = re.compile(
    r"""(?i)\b([a-z_]*(?:password|passwd|secret|api_?key|token)[a-z_]*)\s*[:=]\s*['"]([^'"\s]{8,})['"]""")


def _looks_placeholder(v: str) -> bool:
    low = v.lower()
    return any(h in low for h in PLACEHOLDER_HINTS) or len(set(v)) <= 3


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _Acc:
    def __init__(self) -> None:
        self.env: dict[str, dict] = {}
        self.clients: list[ClientFinding] = []
        self.vulns: dict[tuple[str, str, int], VulnFinding] = {}

    def add_env(self, name: str | None, file: str, line: int, via: str, conf: float, required: bool) -> None:
        if not name or not VALID_NAME.match(name) or name in IGNORED_ENV:
            return
        e = self.env.setdefault(name, {"sources": [], "conf": 0.0, "required": False})
        if not any(s.file == file and s.line == line for s in e["sources"]):
            if len(e["sources"]) < 8:
                e["sources"].append(SourceRef(file=file, line=line, via=via))
        e["conf"] = max(e["conf"], conf)
        e["required"] = e["required"] or required

    def add_vuln(self, rule: str, sev: Severity, file: str, line: int, title: str, detail: str, conf: float) -> None:
        self.vulns.setdefault((rule, file, line), VulnFinding(
            rule_id=rule, severity=sev, file=file, line=line, title=title, detail=detail, confidence=conf))


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, file: str, acc: _Acc, consts: dict[str, str], is_test: bool) -> None:
        self.file, self.acc, self.consts, self.is_test = file, acc, consts, is_test

    def _resolve(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        return None

    @staticmethod
    def _is_environ(node: ast.AST) -> bool:
        return _dotted(node) in {"os.environ", "environ"}

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.ctx, ast.Load) and self._is_environ(node.value):
            self.acc.add_env(self._resolve(node.slice), self.file, node.lineno, "os.environ[]", 0.95, True)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if any((_dotted(b) or "").split(".")[-1] == "BaseSettings" for b in node.bases):
            for st in node.body:
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    self.acc.add_env(st.target.id.upper(), self.file, st.lineno, "pydantic.BaseSettings",
                                     0.5, st.value is None)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            if _dotted(t) == "stripe.api_key":
                self.acc.clients.append(ClientFinding(client="Stripe", file=self.file, line=node.lineno,
                                                      env_hints=["STRIPE_API_KEY"]))
                self.acc.add_env("STRIPE_API_KEY", self.file, node.lineno, "client:Stripe", 0.6, False)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func) or ""
        tail = name.split(".")[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if name in ENV_GET and node.args:
            has_default = len(node.args) > 1 or "default" in kw
            self.acc.add_env(self._resolve(node.args[0]), self.file, node.lineno, name,
                             0.9 if has_default else 0.8, not has_default)
        elif name in ENV_HELPERS and node.args:
            has_default = len(node.args) > 1 or "default" in kw
            self.acc.add_env(self._resolve(node.args[0]), self.file, node.lineno, name, 0.6, not has_default)
        spec = CLIENTS_BY_DOTTED.get(name) or CLIENTS_BY_TAIL.get(tail)
        if spec:
            label, hints, conf = spec
            self.acc.clients.append(ClientFinding(client=label, file=self.file, line=node.lineno, env_hints=hints))
            for h in hints:
                self.acc.add_env(h, self.file, node.lineno, f"client:{label}", conf, False)
        self._vulns(node, name, kw)
        self.generic_visit(node)

    def _vulns(self, node: ast.Call, name: str, kw: dict[str, ast.AST]) -> None:
        f, ln, a = self.file, node.lineno, self.acc
        if name in {"eval", "exec"}:
            a.add_vuln("PY-EVAL", Severity.high, f, ln, f"Use of {name}()", "Dynamic code execution.", 0.9)
        if name == "os.system" or (name.startswith("subprocess.") and
                                   isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True):
            a.add_vuln("PY-SHELL", Severity.high, f, ln, "Shell command execution",
                       "shell=True / os.system enables command injection with untrusted input.", 0.8)
        if name in {"pickle.load", "pickle.loads", "cPickle.loads", "marshal.loads", "shelve.open"}:
            a.add_vuln("PY-DESERIALIZE", Severity.high, f, ln, f"Unsafe deserialization ({name})",
                       "Untrusted data can execute code.", 0.7)
        if name in {"yaml.load", "yaml.load_all"}:
            loader = _dotted(kw["Loader"]) if "Loader" in kw else (_dotted(node.args[1]) if len(node.args) > 1 else None)
            if not loader or "Safe" not in loader:
                a.add_vuln("PY-YAML-LOAD", Severity.high, f, ln, "yaml.load without SafeLoader",
                           "Use yaml.safe_load.", 0.85)
        if "verify" in kw and isinstance(kw["verify"], ast.Constant) and kw["verify"].value is False:
            a.add_vuln("PY-TLS-VERIFY", Severity.medium, f, ln, "TLS verification disabled", "verify=False.", 0.9)
        if name in {"hashlib.md5", "hashlib.sha1"}:
            a.add_vuln("PY-WEAK-HASH", Severity.low, f, ln, f"Weak hash ({name})", "Not collision resistant.", 0.6)
        if name == "tempfile.mktemp":
            a.add_vuln("PY-MKTEMP", Severity.medium, f, ln, "tempfile.mktemp race", "Use mkstemp.", 0.85)
        if name.endswith(".run") and isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            a.add_vuln("PY-DEBUG-SERVER", Severity.medium, f, ln, "Debug server enabled", "debug=True.", 0.7)
        if name.endswith(".execute") and node.args:
            q = node.args[0]
            risky = isinstance(q, ast.JoinedStr) or (isinstance(q, ast.BinOp) and (
                isinstance(q.op, ast.Mod) or (isinstance(q.op, ast.Add) and not (
                    isinstance(q.left, ast.Constant) and isinstance(q.right, ast.Constant)))
            )) or (isinstance(q, ast.Call) and (_dotted(q.func) or "").endswith(".format"))
            if risky:
                a.add_vuln("PY-SQLI", Severity.high, f, ln, "SQL built by string formatting",
                           "Use parameterised queries.", 0.7)
        if name in {f"requests.{m}" for m in ("get", "post", "put", "delete", "patch", "head", "request")} \
                and "timeout" not in kw and not any(k.arg is None for k in node.keywords):
            a.add_vuln("PY-NO-TIMEOUT", Severity.low, f, ln, "HTTP call without timeout",
                       "Can hang indefinitely; a classic source of CI flakiness.", 0.7)
        if self.is_test and name == "time.sleep":
            a.add_vuln("FLAKY-SLEEP", Severity.low, f, ln, "sleep() in test",
                       "Timing-dependent tests are flaky; wait on a condition instead.", 0.5)


def _scan_py(rel: str, text: str, acc: _Acc) -> bool:
    try:
        tree = ast.parse(text, filename=rel)
    except (SyntaxError, ValueError, RecursionError):
        return False
    consts = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
              and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
              for t in n.targets if isinstance(t, ast.Name)}
    is_test = "test" in Path(rel).name.lower() or "/tests/" in f"/{rel}"
    _PyVisitor(rel, acc, consts, is_test).visit(tree)
    return True


def _scan_regex(rel: str, name: str, suffix: str, text: str, acc: _Acc, registry: SecretRegistry) -> None:
    is_template = name.startswith(".env") and name.endswith(ENV_TEMPLATE_SUFFIXES)
    patterns = list(NODE_ENV_PATTERNS)
    if suffix == ".py":
        patterns += PY_FALLBACK_PATTERNS
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for pat, via in patterns:
            for m in pat.finditer(line):
                acc.add_env(m.group(1), rel, i, via, 0.9, False)
        if suffix in {".yml", ".yaml", ".sh", ".bash"} or name in SPECIAL_NAMES:
            for m in SHELL_VAR.finditer(line):
                acc.add_env(m.group(1), rel, i, "shell-expansion", 0.55, not m.group(2))
            for m in GHA_SECRET.finditer(line):
                acc.add_env(m.group(1), rel, i, "github-secrets", 0.6, False)
        if is_template:
            m = DOTENV_LINE.match(line)
            if m:
                acc.add_env(m.group(1), rel, i, "env-template", 0.85, True)


def _scan_secrets(rel: str, suffix: str, text: str, acc: _Acc, registry: SecretRegistry, is_test: bool) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for kind, pat in SECRET_PATTERNS:
            if kind == "private-key":
                continue
            for m in pat.finditer(line):
                if _looks_placeholder(m.group(0)):
                    continue
                registry.add(m.group(0))
                acc.add_vuln(f"SECRET-{kind.upper()}", Severity.critical, rel, i, f"Hardcoded {kind}",
                             "Value redacted. Rotate it and load from the environment.", 0.9)
        if suffix in CODE_SUFFIXES and "environ" not in line and "getenv" not in line:
            m = HARDCODED_ASSIGN.search(line)
            if m and not _looks_placeholder(m.group(2)):
                registry.add(m.group(2))
                acc.add_vuln("SECRET-ASSIGN", Severity.high, rel, i, f"Hardcoded credential in `{m.group(1)}`",
                             "Value redacted. Load from the environment.", 0.3 if is_test else 0.5)
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        for m in SECRET_PATTERNS[8][1].finditer(text):
            registry.add(m.group(0))
            ln = text.count("\n", 0, m.start()) + 1
            acc.add_vuln("SECRET-PRIVATE-KEY", Severity.critical, rel, ln, "Committed private key",
                         "Value redacted. Rotate the key.", 0.95)


def _wanted(name: str, suffix: str) -> bool:
    if name == ".env" or (name.startswith(".env.") and not name.endswith(ENV_TEMPLATE_SUFFIXES)):
        return False  # real env files may hold live secrets: never read them
    return suffix in CODE_SUFFIXES or suffix in CONFIG_SUFFIXES or name in SPECIAL_NAMES or name.startswith(".env")


def scan_workspace(root: Path, registry: SecretRegistry, max_files: int = 5000) -> ScanCredentialsOutput:
    acc, scanned = _Acc(), 0
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            suffix = p.suffix.lower()
            if not _wanted(fn, suffix) or p.is_symlink():
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if scanned >= max_files:
                break
            scanned += 1
            rel = p.relative_to(root).as_posix()
            ok = _scan_py(rel, text, acc) if suffix == ".py" else False
            if suffix != ".py" or not ok:
                _scan_regex(rel, fn, suffix, text, acc, registry)
            is_test = "test" in fn.lower() or "/tests/" in f"/{rel}"
            if suffix not in {".md", ".txt"} or "BEGIN" in text:
                _scan_secrets(rel, suffix, text, acc, registry, is_test)
        else:
            continue
        break
    env = [EnvVarFinding(name=n, sensitive=bool(SENSITIVE_RE.search(n)), required=d["required"],
                         confidence=round(d["conf"], 2), sources=d["sources"]) for n, d in acc.env.items()]
    env.sort(key=lambda e: (-e.confidence, e.name))
    order = {s: i for i, s in enumerate(Severity)}
    vulns = sorted(acc.vulns.values(), key=lambda v: (order[v.severity], -v.confidence, v.file, v.line))
    return ScanCredentialsOutput(files_scanned=scanned, env_vars=env, clients=acc.clients[:100],
                                 vulnerabilities=vulns[:300])
