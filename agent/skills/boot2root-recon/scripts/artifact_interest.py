"""Classify interesting exposed paths and files for CTF/lab recon."""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse, unquote

MAX_FILE_SIZE_MB = 10
MAX_FILES_PER_SERVICE = 50
MAX_TOTAL_MB = 100
MAX_DEPTH = 7

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov", ".webm", ".map"
}

CATEGORIES: list[tuple[str, list[str], int]] = [
    ("flag", [r"flag", r"proof", r"user\.txt$", r"root\.txt$"], 100),
    ("credential", [r"pass(word)?", r"cred", r"secret", r"token", r"api[_-]?key", r"id_rsa", r"authorized_keys", r"shadow", r"passwd"], 95),
    ("config", [r"\.env$", r"config", r"settings", r"wp-config", r"database\.yml", r"application\.properties"], 85),
    ("database", [r"\.sql$", r"\.sqlite$", r"\.db$", r"dump", r"dump\.rdb$", r"appendonly\.aof$"], 85),
    ("backup", [r"backup", r"\.bak$", r"\.old$", r"\.orig$", r"\.zip$", r"\.tar(\.gz)?$", r"\.7z$", r"\.rar$"], 75),
    ("vcs", [r"\.git", r"\.svn", r"\.hg"], 80),
    ("cloud-ci", [r"aws", r"kubeconfig", r"terraform\.tfstate", r"\.gitlab-ci", r"jenkins", r"docker-compose", r"Dockerfile"], 70),
    ("log", [r"\.log$", r"error_log", r"auth\.log", r"laravel\.log", r"debug"], 65),
    ("source", [r"package\.json$", r"composer\.json$", r"requirements\.txt$", r"pom\.xml$", r"\.php$", r"\.py$", r"\.js$"], 45),
    ("document", [r"note", r"report", r"secret", r"backup", r"user", r"root", r"flag", r"proof", r"credential", r"password"], 40),
]

DOC_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx"}


def normalize_path(path: str) -> str:
    parsed = urlparse(path)
    value = parsed.path if parsed.scheme else path
    return unquote(value).lower()


def depth(path: str) -> int:
    return len([p for p in normalize_path(path).split("/") if p])


def classify(path: str) -> tuple[str, str, int]:
    p = normalize_path(path)
    ext = os.path.splitext(p)[1]
    if ext in SKIP_EXTENSIONS:
        return "skip", "static/media extension", 0
    for category, patterns, score in CATEGORIES:
        if category == "document" and ext not in DOC_EXTENSIONS:
            continue
        for pattern in patterns:
            if re.search(pattern, p, re.IGNORECASE):
                return category, f"matched {pattern}", score
    return "", "", 0


def interest_score(path: str) -> int:
    return classify(path)[2]


def interest_reason(path: str) -> str:
    return classify(path)[1]


def is_interesting_path(path: str) -> bool:
    return interest_score(path) >= 40 and depth(path) <= MAX_DEPTH


def should_download(path: str, size: int | None = None) -> bool:
    if not is_interesting_path(path):
        return False
    if size is not None and size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return False
    return True
