"""Unit tests for secret redaction and masking routines."""

from sentinelpr.security.redaction import mask_secret, redact_dict, redact_text


def test_mask_secret_is_deterministic_and_safe():
    secret = "my_super_secret_token_12345"
    masked1 = mask_secret(secret)
    masked2 = mask_secret(secret)

    assert masked1 == masked2
    assert "12345" not in masked1
    assert masked1.startswith("[REDACTED_SECRET_")


def test_redact_aws_keys():
    text = "Deploying with AKIAIOSFODNN7EXAMPLE and key aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    redacted = redact_text(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_SECRET_" in redacted


def test_redact_github_pat():
    text = "Token: ghp_1234567890abcdef1234567890abcdef1234"
    redacted = redact_text(text)

    assert "ghp_1234567890abcdef" not in redacted
    assert "[REDACTED_SECRET_" in redacted


def test_redact_stripe_key():
    text = "Stripe secret: sk_live_51ABCDEF1234567890abcdef1234567890"
    redacted = redact_text(text)

    assert "sk_live_51ABCDEF" not in redacted
    assert "[REDACTED_SECRET_" in redacted


def test_redact_database_url_password():
    text = "Connecting to postgres://admin:super_secret_db_pass@db.internal:5432/production"
    redacted = redact_text(text)

    assert "super_secret_db_pass" not in redacted
    assert "postgres://admin:[REDACTED_SECRET_" in redacted
    assert "@db.internal:5432/production" in redacted


def test_redact_generic_secret_assignment():
    text = 'api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"'
    redacted = redact_text(text)

    assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" not in redacted
    assert 'api_key="[REDACTED_SECRET_' in redacted


def test_redact_dict_recursively():
    data = {
        "user": "developer",
        "api_key": "topsecretkey1234567890",
        "nested": {
            "password": "mysecretpassword",
            "safe_list": ["clean", "ghp_1234567890abcdef1234567890abcdef1234"],
        },
    }
    cleaned = redact_dict(data)

    assert cleaned["user"] == "developer"
    assert "topsecretkey" not in cleaned["api_key"]
    assert "mysecretpassword" not in cleaned["nested"]["password"]
    assert "ghp_" not in cleaned["nested"]["safe_list"][1]
