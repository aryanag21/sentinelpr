"""GitHub Pull Request review comments and summary publication."""

from __future__ import annotations

import logging
from typing import Any

from sentinelpr.github.client import GitHubClient, GitHubClientError
from sentinelpr.models import Finding, Severity

logger = logging.getLogger(__name__)


def format_finding_comment(finding: Finding) -> str:
    """Formats a single finding into a secure GitHub markdown comment."""
    sev_emoji = {
        Severity.CRITICAL: "🚨",
        Severity.HIGH: "🛑",
        Severity.MEDIUM: "⚠️",
        Severity.LOW: "ℹ️",
        Severity.INFO: "💡",
    }.get(finding.severity, "⚠️")

    lines = [
        f"### {sev_emoji} [{finding.severity.value}] {finding.title}",
        "",
        f"**Category:** `{finding.category.value}` | **Source:** `{finding.source}`",
    ]
    if finding.rule_id:
        lines.append(f"**Rule:** `{finding.rule_id}` | **Confidence:** `{finding.confidence}`")

    lines.extend(
        [
            "",
            finding.description,
            "",
            "**Evidence:**",
            "```",
            finding.evidence,
            "```",
        ]
    )

    if finding.remediation:
        lines.extend(
            [
                "",
                "**Recommended Remediation:**",
                f"> {finding.remediation}",
            ]
        )

    return "\n".join(lines)


def publish_pull_request_review(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
    commit_sha: str,
    findings: list[Finding],
    summary: str,
    max_inline_comments: int = 25,
) -> dict[str, Any]:
    """Publishes a PR review with inline comments and a summary comment.

    Enforces maximum inline comment cap to prevent spam and degradation.
    Falls back to a summary-only comment if inline comments fail.
    """
    endpoint = f"repos/{owner}/{repo}/pulls/{pull_number}/reviews"

    # Select candidate inline findings (up to max_inline_comments)
    # Prioritise CRITICAL and HIGH findings for inline display
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            0
            if f.severity == Severity.CRITICAL
            else (1 if f.severity == Severity.HIGH else (2 if f.severity == Severity.MEDIUM else 3))
        ),
    )

    inline_candidates = sorted_findings[:max_inline_comments]
    comments_payload = []

    for f in inline_candidates:
        if f.file_path and f.line_start > 0:
            comments_payload.append(
                {
                    "path": f.file_path,
                    "line": f.line_start,
                    "side": "RIGHT",
                    "body": format_finding_comment(f),
                }
            )

    # Prepare review body
    full_body = summary
    if len(findings) > max_inline_comments:
        full_body += (
            f"\n\n> ⚠️ *Note: Only the top {max_inline_comments} findings were posted inline. "
            f"Please check the Check Run details for all {len(findings)} findings.*"
        )

    review_data: dict[str, Any] = {
        "commit_id": commit_sha,
        "body": full_body,
        "event": "COMMENT",
    }
    if comments_payload:
        review_data["comments"] = comments_payload

    try:
        resp = client.post(endpoint, json_data=review_data)
        if resp.status_code in (200, 201):
            return resp.json()

        # If 422 occurred (e.g. line numbers not part of diff), retry without inline comments
        if resp.status_code == 422:
            logger.warning(
                "PR review with inline comments rejected (422), falling back to summary-only"
            )
            review_data.pop("comments", None)
            fallback_resp = client.post(endpoint, json_data=review_data)
            if fallback_resp.status_code in (200, 201):
                return fallback_resp.json()
            raise GitHubClientError(f"Failed posting summary review: {fallback_resp.text}")

        raise GitHubClientError(f"Failed posting PR review ({resp.status_code}): {resp.text}")

    except Exception as e:
        logger.error("Error submitting GitHub review: %s. Falling back to issue comment.", e)
        return publish_fallback_issue_comment(client, owner, repo, pull_number, full_body)


def publish_fallback_issue_comment(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
    comment_body: str,
) -> dict[str, Any]:
    """Posts a standard PR/issue comment when review API is unavailable."""
    endpoint = f"repos/{owner}/{repo}/issues/{pull_number}/comments"
    resp = client.post(endpoint, json_data={"body": comment_body})
    if resp.status_code not in (200, 201):
        raise GitHubClientError(f"Failed posting fallback issue comment: {resp.text}")
    return resp.json()
