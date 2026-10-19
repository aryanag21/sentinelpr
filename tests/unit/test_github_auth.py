"""Unit tests for GitHub App authentication."""

import httpx
import jwt
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinelpr.github.auth import GitHubAppAuth


def _generate_test_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def test_generate_jwt():
    pem = _generate_test_key_pem()
    auth = GitHubAppAuth(app_id=12345, private_key_pem=pem)
    token = auth.generate_jwt()

    assert token is not None
    # Decode unverified to inspect claims
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["iss"] == "12345"
    assert decoded["exp"] > decoded["iat"]


@respx.mock
def test_get_installation_token_and_cache():
    pem = _generate_test_key_pem()
    auth = GitHubAppAuth(app_id=12345, private_key_pem=pem)

    route = respx.post("https://api.github.com/app/installations/55555/access_tokens").mock(
        return_value=httpx.Response(
            201,
            json={"token": "ghs_mock_access_token_123", "expires_at": "2030-01-01T00:00:00Z"},
        )
    )

    t1 = auth.get_installation_token(55555)
    assert t1 == "ghs_mock_access_token_123"
    assert route.call_count == 1

    # Second call should use cache
    t2 = auth.get_installation_token(55555)
    assert t2 == "ghs_mock_access_token_123"
    assert route.call_count == 1
