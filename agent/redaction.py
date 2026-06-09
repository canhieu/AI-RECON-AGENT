"""Redaction helpers for UI, DB, and reports."""

from __future__ import annotations

import re

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("credential", re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|token|secret|authorization|bearer)\b\s*[:=]\s*['\"]?[^'\"\s]{4,}")),
    ("connection_string", re.compile(r"(?i)\b(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]+")),
    ("long_hex", re.compile(r"\b[a-fA-F0-9]{48,}\b")),
    ("long_base64", re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")),
]

PROOF_NAME_RE = re.compile(r"(?i)(^|[/_.-])(flag|user|root|proof)\.txt$")


def redact_text(value, proof_like: bool = False) -> str:
    """Best-effort masking for presentation/report safety, not a guarantee."""
    text = "" if value is None else str(value)
    if proof_like:
        return "[REDACTED:proof-like-artifact]"
    for label, pattern in SECRET_PATTERNS:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text


def is_proof_like_path(path: str) -> bool:
    return bool(PROOF_NAME_RE.search(str(path or "")))


def redact_mapping(item: dict) -> dict:
    proof_like = is_proof_like_path(item.get("local_path", "")) or is_proof_like_path(item.get("source", ""))
    out = {}
    for key, value in item.items():
        if key in {"summary", "detail", "evidence", "reason", "source"}:
            out[key] = redact_text(value, proof_like=proof_like and key == "evidence")
        else:
            out[key] = value
    return out





def is_proof_like_path(path: str) -> bool:
    return bool(PROOF_NAME_RE.search(str(path or "")))


def redact_mapping(item: dict) -> dict:
    proof_like = is_proof_like_path(item.get("local_path", "")) or is_proof_like_path(item.get("source", ""))
    out = {}
    for key, value in item.items():
        if key in {"summary", "detail", "evidence", "reason", "source"}:
            out[key] = redact_text(value, proof_like=proof_like and key == "evidence")
        else:
            out[key] = value
    return out
