"""Unit tests for GitHub webhook HMAC-SHA256 signature verification."""

import hashlib
import hmac

import pytest

from sentinelpr.security.signature import SignatureVerificationError, verify_github_signature


def _compute_sig(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def test_valid_signature():
    secret = "super_secret_webhook_key_123"
    body = b'{"action":"opened","pull_request":{"id":123}}'
    sig = _compute_sig(secret, body)

    assert verify_github_signature(body, secret, sig) is True


def test_invalid_signature_raises():
    secret = "super_secret_webhook_key_123"
    body = b'{"action":"opened"}'
    invalid_sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000"

    with pytest.raises(SignatureVerificationError, match="Signature mismatch"):
        verify_github_signature(body, secret, invalid_sig)


def test_missing_signature_header_raises():
    secret = "test_secret"
    body = b"hello"
    with pytest.raises(SignatureVerificationError, match="Missing X-Hub-Signature-256 header"):
        verify_github_signature(body, secret, None)


def test_malformed_signature_header_raises():
    secret = "test_secret"
    body = b"hello"
    with pytest.raises(SignatureVerificationError, match="Malformed"):
        verify_github_signature(body, secret, "invalid_prefix_without_sha256")


def test_missing_secret_raises():
    body = b"hello"
    with pytest.raises(SignatureVerificationError, match="Webhook secret is not configured"):
        verify_github_signature(body, "", "sha256=abcdef")
