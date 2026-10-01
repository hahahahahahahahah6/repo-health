#!/usr/bin/env python3
"""repo-health: one-command repository hygiene check.

Run `repo-health [path]` and get a pass/warn/fail checklist for the basics
people always forget: LICENSE, README, .gitignore, committed secrets,
fat files, TODO pile-up, and non-stdlib Python imports.

Exit code 0 if no check FAILED, 1 if any check failed.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from typing import Any

VERSION = "0.1.0"

LICENSE_NAMES = {"license", "licence", "copying"}
# Name patterns that are suspicious on their own.
SECRET_PATTERNS = (".env", "*.pem", "*.key", "id_rsa*", "*credentials*")
# "*secret*" only counts for non-source files: secrets.py / secret.py are
# ordinary module names (stdlib even has a `secrets` module).
SECRET_NAME_RE = re.compile(r"secret", re.IGNORECASE)
SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs",
    ".java", ".rb", ".c", ".h", ".cpp", ".hpp", ".cs", ".php", ".swift",
    ".kt", ".scala", ".sh", ".pl", ".pm",
}

try:
    STDLIB_MODULE_NAMES = sys.stdlib_module_names
except AttributeError:  # Python < 3.10: curated fallback of common modules
    STDLIB_MODULE_NAMES = frozenset({
        "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii",
        "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
        "cmath", "cmd", "code", "codecs", "codeop", "collections",
        "colorsys", "compileall", "concurrent", "configparser",
        "contextlib", "contextvars", "copy", "copyreg", "cProfile",
        "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime",
        "dbm", "decimal", "difflib", "dis", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
        "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
        "imp", "importlib", "inspect", "io", "ipaddress", "itertools",
        "json", "keyword", "lib2to3", "linecache", "locale", "logging",
        "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
        "mmap", "modulefinder", "multiprocessing", "netrc", "nis",
        "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
        "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
        "platform", "plistlib", "poplib", "posix", "pprint", "profile",
        "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
        "quopri", "random", "re", "readline", "reprlib", "resource",
        "rlcompleter", "runpy", "sched", "secrets", "select",
        "selectors", "shelve", "shlex", "shutil", "signal", "site",
        "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
        "sqlite3", "ssl", "stat", "statistics", "string", "stringprep",
        "struct", "subprocess", "sunau", "symtable", "sys", "sysconfig",
        "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
        "test", "textwrap", "threading", "time", "timeit", "tkinter",
        "token", "tokenize", "trace", "traceback", "tracemalloc", "tty",
        "turtle", "turtledemo", "types", "typing", "unicodedata",
        "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave",
        "weakref", "webbrowser", "wsgiref", "xdrlib", "xml", "xmlrpc",
        "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo",
        "_thread", "__future__",
    })
FAT_BYTES = 1024 * 1024
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([a-zA-Z_][\w.]*)|import\s+([a-zA-Z_][\w.]*(?:\s*,\s*[a-zA-Z_][\w.]*)*))"
)
TOP_LEVEL_STDLIB_EXEMPT = {"__future__"}


def iter_files(root: str):
    """Yield paths relative to root, skipping .git (walk fallback)."""
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, root)


def _git_files(root: str):
    """Files as git sees them (tracked + untracked-but-not-ignored),
    as paths relative to `root`. Returns None when git can't answer
    (not a repo, git missing), in which case callers fall back to a walk.
    """
    try:
        top = subprocess.run(
            ["git", "-C", root, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
        )
        if top.returncode != 0:
            return None
        toplevel = top.stdout.strip()
        proc = subprocess.run(
            ["git", "-C", toplevel, "ls-files", "-z", "--full-name",
             "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=False,
        )
        if proc.returncode != 0:
            return None
        rel_root = os.path.relpath(root, toplevel)
        names = []
        for p in proc.stdout.decode("utf-8", "replace").split("\x00"):
            if not p:
                continue
            if rel_root == ".":
                names.append(p)
            elif p == rel_root or p.startswith(rel_root + "/"):
                names.append(os.path.relpath(p, rel_root))
        return names
    except OSError:
        return None


def list_files(root: str):
    """File discovery: ask git first (respects .gitignore), walk on fallback."""
    git_names = _git_files(root)
    if git_names is not None:
        return git_names
    return list(iter_files(root))


def is_secret_name(name: str) -> bool:
    """True if the filename alone is suspicious.

    `.env` / `*.pem` / `*.key` / `id_rsa*` / `*credentials*` always count.
    `*secret*` only counts for non-source files: secrets.py / secret.py are
    ordinary module names, never proof of a committed secret.
    """
    base = os.path.basename(name)
    for pat in SECRET_PATTERNS:
        if fnmatch.fnmatch(base, pat):
            return True
    if SECRET_NAME_RE.search(base):
        return os.path.splitext(base)[1].lower() not in SOURCE_EXTS
    return False


def looks_binary(full: str, size: int) -> bool:
    """Sniff for null bytes; treat unreadable as non-text."""
    try:
        with open(full, "rb") as f:
            return b"\x00" in f.read(min(size, 8192))
    except OSError:
        return True


def is_text_file(full: str, size: int) -> bool:
    return size > 0 and not looks_binary(full, size)


def find_local_modules(root: str) -> set[str]:
    """Top-level module names importable from the repo root (packages + .py files)."""
    mods: set[str] = set()
    try:
        for entry in os.listdir(root):
            full = os.path.join(root, entry)
            if entry.endswith(".py") and os.path.isfile(full):
                mods.add(entry[:-3])
            elif os.path.isdir(full) and os.path.isfile(
                os.path.join(full, "__init__.py")
            ):
                mods.add(entry)
    except OSError:
        pass
    return mods


def extract_imports(full: str, size: int) -> set[str]:
    """Top-level imported module names from a Python file; relative imports skipped."""
    found: set[str] = set()
    if not is_text_file(full, size):
        return found
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.lstrip().startswith("from .") or line.lstrip().startswith(
                    "from  ."
                ):
                    continue
                if re.match(r"^\s*from\s+\.", line):
                    continue
                m = IMPORT_RE.match(line)
                if not m:
                    continue
                raw = m.group(1) or m.group(2)
                for part in raw.split(","):
                    part = part.strip()
                    # drop `as` aliases
                    part = re.split(r"\s+as\s+", part)[0].strip()
                    top = part.split(".")[0]
                    if top:
                        found.add(top)
    except OSError:
        pass
    return found


def check(root: str) -> list[dict[str, Any]]:
    names = list_files(root)
    results: list[dict[str, Any]] = []

    # 1. license
    lic = [n for n in names if os.path.splitext(os.path.basename(n))[0].lower() in LICENSE_NAMES]
    results.append(
        {
            "check": "license",
            "status": "PASS" if lic else "FAIL",
            "detail": lic[0] if lic else "no LICENSE/LICENCE/COPYING found",
        }
    )

    # 2. readme
    rds = [n for n in names if os.path.basename(n).lower().startswith("readme")]
    results.append(
        {
            "check": "readme",
            "status": "PASS" if rds else "FAIL",
            "detail": rds[0] if rds else "no README found",
        }
    )

    # 3. gitignore
    gis = [n for n in names if os.path.basename(n) == ".gitignore"]
    results.append(
        {
            "check": "gitignore",
            "status": "PASS" if gis else "WARN",
            "detail": gis[0] if gis else "no .gitignore found",
        }
    )

    # 4. secrets — flag names only, never print contents
    flagged = sorted({n for n in names if is_secret_name(n)})
    results.append(
        {
            "check": "secrets",
            "status": "FAIL" if flagged else "PASS",
            "detail": f"{len(flagged)} suspicious file(s): " + ", ".join(flagged)
            if flagged
            else "no secret-like filenames found",
        }
    )

    # 5. fat files
    fats: list[tuple[int, str]] = []
    for n in names:
        full = os.path.join(root, n)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if size > FAT_BYTES:
            fats.append((size, n))
    fats.sort(reverse=True)
    results.append(
        {
            "check": "fat-files",
            "status": "WARN" if fats else "PASS",
            "detail": f"{len(fats)} file(s) over 1MB: "
            + ", ".join(f"{n} ({s / FAT_BYTES:.1f}MB)" for s, n in fats[:5])
            if fats
            else "no files over 1MB",
        }
    )

    # 6. todos
    todos = 0
    for n in names:
        full = os.path.join(root, n)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if not is_text_file(full, size):
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                todos += sum(len(TODO_RE.findall(line)) for line in f)
        except OSError:
            continue
    results.append(
        {
            "check": "todos",
            "status": "WARN" if todos > 20 else "PASS",
            "detail": f"{todos} TODO/FIXME/XXX/HACK markers",
        }
    )

    # 7. stdlib-only
    pyfiles = [n for n in names if n.endswith(".py")]
    local = find_local_modules(root)
    third_party: set[str] = set()
    for n in pyfiles:
        for mod in extract_imports(os.path.join(root, n), _size(root, n)):
            if mod in TOP_LEVEL_STDLIB_EXEMPT or mod in STDLIB_MODULE_NAMES:
                continue
            if mod in local:
                continue
            third_party.add(mod)
    results.append(
        {
            "check": "stdlib-only",
            "status": "SKIP" if not pyfiles else ("WARN" if third_party else "PASS"),
            "detail": "no Python files" if not pyfiles else (
                "third-party imports: " + ", ".join(sorted(third_party))
                if third_party
                else "all imports are stdlib or local"
            ),
        }
    )

    return results


def _size(root: str, rel: str) -> int:
    try:
        return os.path.getsize(os.path.join(root, rel))
    except OSError:
        return 0


def render_text(results: list[dict[str, Any]], root: str) -> str:
    width = max(len(r["check"]) for r in results)
    lines = [f"repo-health {VERSION} — {root}", ""]
    for r in results:
        mark = {"PASS": "✓", "WARN": "!", "FAIL": "✗", "SKIP": "-"}.get(r["status"], "?")
        lines.append(f"[{mark} {r['status']:4}] {r['check']:{width}}  {r['detail']}")
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    summary = " / ".join(f"{counts[k]} {k.lower()}" for k in ("PASS", "WARN", "FAIL") if counts[k])
    lines += ["", f"summary: {summary}" if summary else "summary: clean"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="One-command repository hygiene check."
    )
    parser.add_argument("path", nargs="?", default=".", help="repo path (default: cwd)")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        print(VERSION)
        return 0

    root = os.path.abspath(args.path)
    results = check(root)

    if args.json:
        print(json.dumps({"repo": root, "version": VERSION, "checks": results}, indent=2))
    else:
        print(render_text(results, root))

    return 1 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
