"""GitHub Check Runs lifecycle management and annotations."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sentinelpr.github.client import GitHubClient, GitHubClientError
from sentinelpr.models import CheckConclusion, Finding, Severity

logger = logging.getLogger(__name__)


def create_check_run(
    client: GitHubClient,
    owner: str,
    repo: str,
    commit_sha: str,
    name: str = "SentinelPR Security Review",
) -> int:
    """Creates a new Check Run in 'in_progress' state and returns its check_run_id."""
    endpoint = f"repos/{owner}/{repo}/check-runs"
    payload = {
        "name": name,
        "head_sha": commit_sha,
        "status": "in_progress",
        "started_at": datetime.now(UTC).isoformat(),
        "output": {
            "title": "SentinelPR Security Audit Running",
            "summary": "Auditing pull request for secrets, vulnerabilities, and misconfigurations...",
        },
    }
    resp = client.post(endpoint, json_data=payload)
    if resp.status_code != 201:
        raise GitHubClientError(f"Failed to create Check Run: {resp.status_code} {resp.text}")
    data = resp.json()
    return int(data["id"])


def complete_check_run(
    client: GitHubClient,
    owner: str,
    repo: str,
    check_run_id: int,
    conclusion: CheckConclusion,
    summary: str,
    findings: list[Finding],
) -> dict[str, Any]:
    """Updates a Check Run to 'completed' with final conclusion and finding annotations."""
    endpoint = f"repos/{owner}/{repo}/check-runs/{check_run_id}"

    # Build annotations (GitHub allows up to 50 annotations per request)
    annotations = []
    for f in findings[:50]:
        if f.file_path and f.line_start > 0:
            level = (
                "failure"
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
                else ("warning" if f.severity == Severity.MEDIUM else "notice")
            )
            annotations.append(
                {
                    "path": f.file_path,
                    "start_line": f.line_start,
                    "end_line": max(f.line_end, f.line_start),
                    "annotation_level": level,
                    "title": f"[{f.severity.value}] {f.title}"[:255],
                    "message": f"{f.description}\n\nRemediation: {f.remediation}"[:1000],
                }
            )

    output_title = f"SentinelPR: {conclusion.value.upper()}"
    if conclusion == CheckConclusion.SUCCESS:
        output_title = "SentinelPR: Clean - No High/Critical Findings"
    elif conclusion == CheckConclusion.FAILURE:
        output_title = "SentinelPR: Failed - Security Action Required"
    elif conclusion == CheckConclusion.NEUTRAL:
        output_title = "SentinelPR: Warnings Detected"

    payload: dict[str, Any] = {
        "status": "completed",
        "conclusion": conclusion.value,
        "completed_at": datetime.now(UTC).isoformat(),
        "output": {
            "title": output_title,
            "summary": summary[:65535],
            "annotations": annotations,
        },
    }

    resp = client.patch(endpoint, json_data=payload)
    if resp.status_code != 200:
        # If annotations failed (e.g. invalid line/path), retry without annotations
        logger.warning(
            "Check Run update failed (%d), retrying without annotations", resp.status_code
        )
        payload["output"]["annotations"] = []
        retry_resp = client.patch(endpoint, json_data=payload)
        if retry_resp.status_code != 200:
            raise GitHubClientError(f"Failed updating Check Run: {retry_resp.text}")
        return retry_resp.json()

    return resp.json()
