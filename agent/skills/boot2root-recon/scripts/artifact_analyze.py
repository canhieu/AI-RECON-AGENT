#!/usr/bin/env python3
"""Analyze local artifacts for suspicious text and redact previews."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

MAX_READ = 256 * 1024
TEXT_EXTS = {".txt", ".log", ".conf", ".cfg", ".ini", ".env", ".bak", ".old", ".sql", ".json", ".xml", ".yml", ".yaml", ".config"}
SUSPICIOUS_NAMES = re.compile(r"(?i)(flag|proof|user|root|pass|cred|secret|token|key|config|backup|db|database|shadow|passwd)")
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.S),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "credential": re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|token|secret|authorization|bearer)\b\s*[:=]\s*['\"]?[^'\"\s]{4,}"),
    "connection_string": re.compile(r"(?i)\b(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]+"),
    "proof_like": re.compile(r"(?i)(^|[/_.-])(flag|user|root|proof)\.txt$"),
}


def redact(text: str, proof_like: bool = False) -> str:
    """Return a preview safe for DB/UI/report; raw file stays untouched."""
    if proof_like:
        return "[REDACTED:proof-like-artifact]"
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED:private_key]", text, flags=re.S)
    text = PATTERNS["jwt"].sub("[REDACTED:jwt]", text)
    text = PATTERNS["credential"].sub("[REDACTED:credential]", text)
    text = PATTERNS["connection_string"].sub("[REDACTED:connection_string]", text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    path = Path(args.path)
    result = {"path": str(path), "exists": path.exists(), "suspicious": False, "risk": "info", "indicators": [], "redacted_preview": "", "sha256": "", "size": 0}
    if not path.exists() or not path.is_file():
        print(json.dumps(result, sort_keys=True))
        return 0
    data = path.read_bytes()[:MAX_READ]
    result["size"] = path.stat().st_size
    result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    text = data.decode("utf-8", "ignore")
    name = str(path)
    proof_like = bool(PATTERNS["proof_like"].search(name))
    if proof_like:
        result["indicators"].append("proof_like_path")
    if path.suffix.lower() in TEXT_EXTS or SUSPICIOUS_NAMES.search(name):
        result["indicators"].append("suspicious_text_artifact")
    for label, pat in PATTERNS.items():
        if label == "proof_like":
            continue
        if pat.search(text):
            result["indicators"].append(label)
    result["indicators"] = sorted(set(result["indicators"]))
    result["suspicious"] = bool(result["indicators"])
    if any(x in result["indicators"] for x in ("private_key", "credential", "connection_string", "proof_like_path")):
        result["risk"] = "high"
    elif result["suspicious"]:
        result["risk"] = "medium"
    result["redacted_preview"] = redact(text[:1200], proof_like=proof_like)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
