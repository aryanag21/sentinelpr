"""Secret redaction and masking utilities.

Ensures no raw credential, token, or private key appears in logs,
terminal outputs, GitHub comments, or AI prompts.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Regex patterns for matching common credentials
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)\baws_(?:secret_access_key|secret_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?"
        ),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
    ),
    (
        "DB_PASSWORD",
        re.compile(r"(?i)\b([a-z]+:\/\/[a-zA-Z0-9_\-\.]+):([^@\s]+)@"),
    ),
    (
        "GENERIC_SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9\-_./+]{16,100})['\"]"
        ),
    ),
]

_SENSITIVE_KEY_NAMES = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "private_key",
    "authorization",
    "x-hub-signature-256",
    "client_secret",
}


def mask_secret(value: str) -> str:
    """Returns a deterministic safe masked representation using a short SHA-256 hash."""
    if not value:
        return "[REDACTED]"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED_SECRET_{digest}]"


def redact_text(text: str) -> str:
    """Scans and replaces recognized secret values within arbitrary text strings."""
    if not text:
        return text

    redacted = text

    # Handle Database connection strings specially to preserve URI scheme and host
    def _replace_db(match: re.Match[str]) -> str:
        prefix = match.group(1)
        pwd = match.group(2)
        return f"{prefix}:{mask_secret(pwd)}@"

    redacted = _SECRET_PATTERNS[6][1].sub(_replace_db, redacted)

    # Handle Generic Key-Value assignments
    def _replace_kv(match: re.Match[str]) -> str:
        key_name = match.group(1)
        secret_val = match.group(2)
        return f'{key_name}="{mask_secret(secret_val)}"'

    redacted = _SECRET_PATTERNS[7][1].sub(_replace_kv, redacted)

    # Handle all other token patterns
    for name, pattern in _SECRET_PATTERNS:
        if name in ("DB_PASSWORD", "GENERIC_SECRET_ASSIGNMENT"):
            continue
        redacted = pattern.sub(lambda m: mask_secret(m.group(0)), redacted)

    return redacted


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redacts dictionary keys and values."""
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        lower_key = str(key).lower()
        if any(sens in lower_key for sens in _SENSITIVE_KEY_NAMES):
            cleaned[key] = mask_secret(str(value))
        elif isinstance(value, dict):
            cleaned[key] = redact_dict(value)
        elif isinstance(value, list):
            cleaned[key] = [
                redact_dict(item)
                if isinstance(item, dict)
                else (redact_text(str(item)) if isinstance(item, str) else item)
                for item in value
            ]
        elif isinstance(value, str):
            cleaned[key] = redact_text(value)
        else:
            cleaned[key] = value
    return cleaned
