"""GitHub Pull Request diff and metadata retrieval."""

from __future__ import annotations

import logging
from typing import Any

from sentinelpr.github.client import GitHubClient, GitHubClientError

logger = logging.getLogger(__name__)

MAX_DIFF_BYTES = 5 * 1024 * 1024  # 5 MB maximum diff
MAX_FILES = 150  # Max files to audit per PR


def get_pull_request_diff(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
) -> str:
    """Retrieves the unified diff of a pull request.

    Enforces bounds on diff size to avoid out-of-memory or runaway processing.
    """
    endpoint = f"repos/{owner}/{repo}/pulls/{pull_number}"
    resp = client.get(endpoint, custom_accept="application/vnd.github.v3.diff")
    if resp.status_code != 200:
        raise GitHubClientError(
            f"Failed to fetch PR diff ({owner}/{repo}#{pull_number}): {resp.status_code} {resp.text}"
        )

    diff_text = resp.text
    if len(diff_text.encode("utf-8")) > MAX_DIFF_BYTES:
        logger.warning("PR diff exceeds size bound (%d bytes), truncating", len(diff_text))
        diff_text = diff_text[:MAX_DIFF_BYTES]

    return diff_text


def get_pull_request_files(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
) -> list[dict[str, Any]]:
    """Retrieves list of changed files for a pull request with pagination and size caps."""
    endpoint = f"repos/{owner}/{repo}/pulls/{pull_number}/files"
    files = client.get_all_pages(endpoint)
    if len(files) > MAX_FILES:
        logger.warning("PR modifies %d files, capping at %d", len(files), MAX_FILES)
        files = files[:MAX_FILES]
    return files


def get_pull_request_metadata(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
) -> dict[str, Any]:
    """Retrieves core PR metadata such as head SHA, base SHA, title, and state."""
    endpoint = f"repos/{owner}/{repo}/pulls/{pull_number}"
    resp = client.get(endpoint)
    if resp.status_code != 200:
        raise GitHubClientError(
            f"Failed to fetch PR metadata ({owner}/{repo}#{pull_number}): {resp.status_code} {resp.text}"
        )
    return resp.json()
