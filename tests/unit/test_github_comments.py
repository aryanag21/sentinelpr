"""Unit tests for GitHub PR comments and reviews."""

import json

import httpx
import respx

from sentinelpr.github.client import GitHubClient
from sentinelpr.github.comments import format_finding_comment, publish_pull_request_review
from sentinelpr.models import Finding, FindingCategory, Severity


def test_format_finding_comment_safe_and_structured():
    finding = Finding(
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        title="Detected Fake Key",
        description="A credential was committed",
        file_path="secrets.py",
        line_start=5,
        line_end=5,
        evidence="[REDACTED_SECRET_abc]",
        remediation="Rotate key immediately.",
        source="gitleaks",
    )
    comment = format_finding_comment(finding)

    assert "[CRITICAL] Detected Fake Key" in comment
    assert "[REDACTED_SECRET_abc]" in comment
    assert "Rotate key immediately." in comment


@respx.mock
def test_publish_pull_request_review_caps_comments():
    client = GitHubClient(token="mock_token")

    route = respx.post("https://api.github.com/repos/org/repo/pulls/10/reviews").mock(
        return_value=httpx.Response(200, json={"id": 999, "state": "COMMENTED"})
    )

    findings = [
        Finding(
            category=FindingCategory.INJECTION,
            severity=Severity.HIGH,
            title=f"Finding {i}",
            description=f"Desc {i}",
            file_path=f"file_{i}.py",
            line_start=i,
            line_end=i,
            evidence="code",
        )
        for i in range(1, 35)  # 34 findings
    ]

    res = publish_pull_request_review(
        client=client,
        owner="org",
        repo="repo",
        pull_number=10,
        commit_sha="abcd1234abcd1234abcd1234abcd1234abcd1234",
        findings=findings,
        summary="Summary of audit",
        max_inline_comments=25,
    )

    assert res["id"] == 999
    sent_dict = json.loads(route.calls[0].request.read().decode("utf-8"))
    assert len(sent_dict.get("comments", [])) == 25  # Capped at 25


@respx.mock
def test_publish_review_fallback_on_422():
    client = GitHubClient(token="mock_token")

    # First call with inline comments returns 422
    # Second retry call without comments returns 200
    respx.post("https://api.github.com/repos/org/repo/pulls/10/reviews").mock(
        side_effect=[
            httpx.Response(422, json={"message": "Unprocessable Entity: invalid diff line"}),
            httpx.Response(200, json={"id": 1001, "state": "COMMENTED"}),
        ]
    )

    finding = Finding(
        category=FindingCategory.CONFIG,
        severity=Severity.MEDIUM,
        title="Invalid diff line test",
        description="desc",
        file_path="old.py",
        line_start=999,
        line_end=999,
        evidence="code",
    )

    res = publish_pull_request_review(
        client=client,
        owner="org",
        repo="repo",
        pull_number=10,
        commit_sha="abcd1234abcd1234abcd1234abcd1234abcd1234",
        findings=[finding],
        summary="Summary text",
    )

    assert res["id"] == 1001
