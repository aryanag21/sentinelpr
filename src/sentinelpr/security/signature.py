"""GitHub Webhook HMAC-SHA256 Signature Verification."""

from __future__ import annotations

import hashlib
import hmac


class SignatureVerificationError(Exception):
    """Raised when GitHub webhook signature verification fails."""


def verify_github_signature(
    raw_body: bytes,
    secret: str,
    signature_header: str | None,
) -> bool:
    """Verifies that the raw webhook request body matches the X-Hub-Signature-256 header.

    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.

    Args:
        raw_body: The raw, unparsed HTTP request body bytes.
        secret: The shared webhook secret configured in the GitHub App.
        signature_header: The value of the X-Hub-Signature-256 header (format: sha256=<hex>).

    Returns:
        True if the signature is valid.

    Raises:
        SignatureVerificationError: If the header is missing, malformed, or doesn't match.
    """
    if not signature_header:
        raise SignatureVerificationError("Missing X-Hub-Signature-256 header")

    if not secret:
        raise SignatureVerificationError("Webhook secret is not configured")

    if not signature_header.startswith("sha256="):
        raise SignatureVerificationError(
            "Malformed X-Hub-Signature-256 header: must start with sha256="
        )

    expected_sig = signature_header.removeprefix("sha256=").strip()

    mac = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    )
    computed_sig = mac.hexdigest()

    if not hmac.compare_digest(computed_sig, expected_sig):
        raise SignatureVerificationError("Signature mismatch: invalid HMAC-SHA256 signature")

    return True
