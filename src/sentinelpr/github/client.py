"""HTTP client for GitHub REST API with rate-limiting and pagination."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GitHubClientError(Exception):
    """Base exception for GitHub API errors."""


class GitHubRateLimitError(GitHubClientError):
    """Raised when GitHub API rate limits are exceeded."""


class GitHubClient:
    """Wrapper around httpx for authenticated GitHub API operations."""

    def __init__(
        self,
        token: str,
        base_url: str = "https://api.github.com",
        timeout: float = 15.0,
    ):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, custom_accept: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": custom_accept or "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SentinelPR-Security-Auditor",
        }

    def request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        custom_accept: str | None = None,
    ) -> httpx.Response:
        """Sends an authenticated request to GitHub API with backoff on rate limits."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._headers(custom_accept)

        max_attempts = 3
        delay = 1.0

        for attempt in range(1, max_attempts + 1):
            with httpx.Client(timeout=self.timeout) as client:
                try:
                    resp = client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json_data,
                    )

                    # Handle secondary rate limits / throttling
                    if resp.status_code in (403, 429):
                        remaining = resp.headers.get("x-ratelimit-remaining")
                        if remaining == "0":
                            reset_time = int(resp.headers.get("x-ratelimit-reset", "0"))
                            sleep_duration = max(reset_time - int(time.time()), 1)
                            if attempt == max_attempts:
                                raise GitHubRateLimitError(
                                    f"GitHub primary rate limit reached. Resets in {sleep_duration}s"
                                )
                            logger.warning("Rate limit hit, waiting %ds", sleep_duration)
                            time.sleep(min(sleep_duration, 10))
                            continue
                        elif "rate limit" in resp.text.lower():
                            if attempt == max_attempts:
                                raise GitHubRateLimitError(
                                    f"GitHub secondary rate limit reached: {resp.text}"
                                )
                            time.sleep(delay)
                            delay *= 2.0
                            continue

                    return resp
                except httpx.TimeoutException as e:
                    if attempt == max_attempts:
                        raise GitHubClientError(f"Request timeout to GitHub ({url}): {e}") from e
                    time.sleep(delay)
                    delay *= 2.0
                except httpx.HTTPError as e:
                    raise GitHubClientError(f"HTTP network error contacting GitHub: {e}") from e

        raise GitHubClientError(f"GitHub request failed after {max_attempts} attempts")

    def get(
        self, endpoint: str, params: dict[str, Any] | None = None, custom_accept: str | None = None
    ) -> httpx.Response:
        return self.request("GET", endpoint, params=params, custom_accept=custom_accept)

    def post(self, endpoint: str, json_data: Any | None = None) -> httpx.Response:
        return self.request("POST", endpoint, json_data=json_data)

    def patch(self, endpoint: str, json_data: Any | None = None) -> httpx.Response:
        return self.request("PATCH", endpoint, json_data=json_data)

    def get_all_pages(
        self, endpoint: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Paginates through a GitHub endpoint and returns all items."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        params.setdefault("page", 1)

        all_items: list[dict[str, Any]] = []
        while True:
            resp = self.get(endpoint, params=params)
            if resp.status_code != 200:
                raise GitHubClientError(
                    f"Failed to fetch page {params['page']} for {endpoint}: {resp.text}"
                )
            data = resp.json()
            if not data or not isinstance(data, list):
                break
            all_items.extend(data)
            if len(data) < params["per_page"]:
                break
            params["page"] += 1

        return all_items
