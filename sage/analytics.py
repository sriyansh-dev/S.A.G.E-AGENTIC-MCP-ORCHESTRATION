"""Codebase analytics: size, languages, Python complexity hotspots, TODOs, test presence."""
import ast
import os
import re
from pathlib import Path

from .scanner import MAX_BYTES, SKIP_DIRS
from .schemas import AnalyticsOutput, FileStat, FunctionMetric

LANG = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
        ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".java": "Java", ".kt": "Kotlin", ".rs": "Rust", ".sh": "Shell",
        ".fish": "Shell", ".html": "HTML", ".css": "CSS", ".md": "Markdown", ".yml": "YAML", ".yaml": "YAML",
        ".json": "JSON", ".toml": "TOML", ".sql": "SQL"}
DEP_FILES = {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "package.json", "go.mod",
             "Cargo.toml", "Gemfile", "pom.xml", "Dockerfile", "docker-compose.yml"}
TODO = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
_BRANCH = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert, ast.With, ast.AsyncWith)


def _complexity(fn: ast.AST) -> int:
    c = 1
    for n in ast.walk(fn):
        if isinstance(n, _BRANCH):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
    return c


def analyze_workspace(root: Path, max_files: int = 5000) -> AnalyticsOutput:
    root = root.resolve()
    loc_by_lang: dict[str, int] = {}
    file_loc: list[FileStat] = []
    funcs: list[FunctionMetric] = []
    todos = tests = files = 0
    deps: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            lang = LANG.get(p.suffix.lower())
            if p.is_symlink() or fn == ".env" or (lang is None and fn not in DEP_FILES):
                continue
            if files >= max_files:
                break
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files += 1
            rel = p.relative_to(root).as_posix()
            if fn in DEP_FILES:
                deps.append(rel)
            if lang is None:
                continue
            lines = [ln for ln in text.splitlines() if ln.strip()]
            loc_by_lang[lang] = loc_by_lang.get(lang, 0) + len(lines)
            if lang not in {"Markdown", "JSON", "YAML", "TOML"}:
                file_loc.append(FileStat(file=rel, loc=len(lines)))
                todos += sum(1 for ln in lines if TODO.search(ln))
            if lang == "Python":
                if fn.startswith("test_") or fn.endswith("_test.py") or "/tests/" in f"/{rel}":
                    tests += 1
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    continue
                for n in ast.walk(tree):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        funcs.append(FunctionMetric(file=rel, name=n.name, line=n.lineno, complexity=_complexity(n),
                                                    length=(n.end_lineno or n.lineno) - n.lineno + 1))
        else:
            continue
        break
    funcs.sort(key=lambda f: (-f.complexity, -f.length))
    avg = round(sum(f.complexity for f in funcs) / len(funcs), 2) if funcs else 0.0
    file_loc.sort(key=lambda f: -f.loc)
    return AnalyticsOutput(files=files, total_loc=sum(loc_by_lang.values()), loc_by_language=loc_by_lang,
                           python_functions=len(funcs), avg_complexity=avg, hotspots=funcs[:8],
                           largest_files=file_loc[:5], todo_count=todos, test_files=tests, has_tests=tests > 0,
                           dependency_files=sorted(deps)[:12])
