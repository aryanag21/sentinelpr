"""Unit tests for GitHub Check Runs lifecycle."""

import httpx
import respx

from sentinelpr.github.checks import complete_check_run, create_check_run
from sentinelpr.github.client import GitHubClient
from sentinelpr.models import CheckConclusion, Finding, FindingCategory, Severity


@respx.mock
def test_create_check_run():
    client = GitHubClient(token="mock_token")

    respx.post("https://api.github.com/repos/org/repo/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 4242, "status": "in_progress"})
    )

    cid = create_check_run(
        client=client,
        owner="org",
        repo="repo",
        commit_sha="abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    assert cid == 4242


@respx.mock
def test_complete_check_run_with_annotations():
    client = GitHubClient(token="mock_token")

    route = respx.patch("https://api.github.com/repos/org/repo/check-runs/4242").mock(
        return_value=httpx.Response(
            200, json={"id": 4242, "status": "completed", "conclusion": "failure"}
        )
    )

    finding = Finding(
        category=FindingCategory.INJECTION,
        severity=Severity.HIGH,
        title="SQL Injection",
        description="Vulnerable SQL query",
        file_path="db.py",
        line_start=15,
        line_end=15,
        evidence="query = f'SELECT...'",
        remediation="Use params",
    )

    res = complete_check_run(
        client=client,
        owner="org",
        repo="repo",
        check_run_id=4242,
        conclusion=CheckConclusion.FAILURE,
        summary="Security audit failed with blockers",
        findings=[finding],
    )

    assert res["status"] == "completed"
    assert res["conclusion"] == "failure"
    assert route.called
