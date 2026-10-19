"""GitHub App authentication using short-lived installation access tokens."""

from __future__ import annotations

import logging
import time
from datetime import datetime

import httpx
import jwt

logger = logging.getLogger(__name__)


class GitHubAuthError(Exception):
    """Raised when GitHub App authentication fails."""


class GitHubAppAuth:
    """Handles GitHub App JWT signing and installation token exchange."""

    def __init__(
        self,
        app_id: int,
        private_key_pem: str,
        base_url: str = "https://api.github.com",
    ):
        self.app_id = app_id
        self.private_key_pem = private_key_pem.strip()
        self.base_url = base_url.rstrip("/")
        # In-memory cache: installation_id -> (token, expiry_epoch)
        self._token_cache: dict[int, tuple[str, float]] = {}

    def generate_jwt(self) -> str:
        """Generates a RS256 JWT for GitHub App authentication (valid for 10 minutes)."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # 60s clock drift allowance
            "exp": now + (10 * 60),  # 10 minutes max
            "iss": str(self.app_id),
        }
        try:
            return jwt.encode(payload, self.private_key_pem, algorithm="RS256")
        except Exception as e:
            raise GitHubAuthError(f"Failed to generate GitHub App JWT: {e}") from e

    def get_installation_token(self, installation_id: int) -> str:
        """Retrieves or exchanges a short-lived installation access token."""
        now = time.time()
        if installation_id in self._token_cache:
            cached_token, expiry = self._token_cache[installation_id]
            if now < (expiry - 120):  # 2 minute buffer
                return cached_token

        jwt_token = self.generate_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        url = f"{self.base_url}/app/installations/{installation_id}/access_tokens"

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, headers=headers)
                if resp.status_code != 201:
                    raise GitHubAuthError(
                        f"Failed to obtain installation token (status {resp.status_code}): {resp.text}"
                    )
                data = resp.json()
                token = data["token"]
                # GitHub tokens usually expire in 1 hour
                # Calculate expiry or use default 3600s
                expires_at_str = data.get("expires_at")
                if expires_at_str:
                    exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    exp_epoch = exp_dt.timestamp()
                else:
                    exp_epoch = now + 3600

                self._token_cache[installation_id] = (token, exp_epoch)
                return token
        except httpx.HTTPError as e:
            raise GitHubAuthError(f"HTTP request error during token exchange: {e}") from e
