"""Unit tests for GitHub HTTP client."""

import httpx
import pytest
import respx

from sentinelpr.github.client import GitHubClient, GitHubRateLimitError


@respx.mock
def test_github_client_get_and_post():
    client = GitHubClient(token="mock_token")

    respx.get("https://api.github.com/repos/org/repo").mock(
        return_value=httpx.Response(200, json={"id": 1, "name": "repo"})
    )
    resp = client.get("repos/org/repo")
    assert resp.status_code == 200
    assert resp.json()["name"] == "repo"


@respx.mock
def test_github_client_pagination():
    client = GitHubClient(token="mock_token")

    respx.get("https://api.github.com/items?per_page=100&page=1").mock(
        return_value=httpx.Response(200, json=[{"id": 1}, {"id": 2}])
    )

    items = client.get_all_pages("items")
    assert len(items) == 2


@respx.mock
def test_github_client_rate_limit_exceeded():
    client = GitHubClient(token="mock_token", timeout=1.0)

    respx.get("https://api.github.com/rate_limited").mock(
        return_value=httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"},
            json={"message": "API rate limit exceeded"},
        )
    )

    with pytest.raises(GitHubRateLimitError):
        client.get("rate_limited")
