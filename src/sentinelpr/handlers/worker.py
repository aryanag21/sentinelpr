"""AWS Lambda Worker Handler: consumes SQS jobs, scans PRs, and reports to GitHub."""

from __future__ import annotations

import json
from typing import Any

import boto3

from sentinelpr.config import get_settings
from sentinelpr.github.auth import GitHubAppAuth
from sentinelpr.github.checks import complete_check_run, create_check_run
from sentinelpr.github.client import GitHubClient
from sentinelpr.github.comments import publish_pull_request_review
from sentinelpr.github.pull_requests import get_pull_request_diff
from sentinelpr.logging_utils import get_logger
from sentinelpr.orchestration import ScanOrchestrator
from sentinelpr.storage.dynamodb import DynamoDBStore

logger = get_logger("sentinelpr.worker")


def get_private_key_pem(settings) -> str:
    """Retrieves GitHub App private key PEM from Secrets Manager or settings."""
    if settings.github_app_private_key_pem:
        return settings.github_app_private_key_pem

    if settings.github_app_private_key_secret_arn:
        sm = boto3.client("secretsmanager")
        res = sm.get_secret_value(SecretId=settings.github_app_private_key_secret_arn)
        return res.get("SecretString", "")

    return ""


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Processes SQS scan job batches."""
    settings = get_settings()
    store = DynamoDBStore(table_name=settings.dynamodb_table_name)
    orchestrator = ScanOrchestrator(
        enable_ai=True,
        offline=False,
        warn_only_mode=settings.warn_only_mode,
        fail_on_high_secrets=settings.fail_on_high_secrets,
    )

    batch_failures: list[dict[str, str]] = []

    for record in event.get("Records", []):
        msg_id = record.get("messageId", "")
        try:
            body = json.loads(record.get("body", "{}"))
            _process_single_job(body, settings, store, orchestrator)
        except Exception as e:
            logger.error("Error processing SQS message %s: %s", msg_id, e)
            batch_failures.append({"itemIdentifier": msg_id})

    return {"batchItemFailures": batch_failures}


def _process_single_job(
    job: dict[str, Any],
    settings,
    store: DynamoDBStore,
    orchestrator: ScanOrchestrator,
) -> None:
    repo = job.get("repository", {})
    repo_id = str(repo.get("id"))
    repo_name = repo.get("name")
    owner = repo.get("owner")

    pr_info = job.get("pull_request", {})
    pr_number = pr_info.get("number")
    commit_sha = pr_info.get("head_sha")
    installation_id = job.get("installation", {}).get("id")

    if not (owner and repo_name and pr_number and commit_sha and installation_id):
        logger.error("Job payload missing required fields: %s", job)
        return

    logger.info(
        "Starting audit for %s/%s PR #%d (commit: %s)", owner, repo_name, pr_number, commit_sha[:7]
    )

    # 1. Authenticate with GitHub App
    pem = get_private_key_pem(settings)
    auth = GitHubAppAuth(app_id=settings.github_app_id or 0, private_key_pem=pem)
    token = auth.get_installation_token(installation_id)
    gh_client = GitHubClient(token=token)

    # 2. Create Check Run in progress
    check_run_id = create_check_run(
        client=gh_client,
        owner=owner,
        repo=repo_name,
        commit_sha=commit_sha,
    )

    # 3. Retrieve diff
    diff_text = get_pull_request_diff(
        client=gh_client,
        owner=owner,
        repo=repo_name,
        pull_number=pr_number,
    )

    # 4. Execute audit
    scan_result = orchestrator.scan_diff(
        diff_content=diff_text,
        repo_id=repo_id,
        pr_number=pr_number,
        commit_sha=commit_sha,
    )

    # 5. Persist scan result and findings to DynamoDB
    store.save_scan_job(scan_result)
    for finding in scan_result.findings:
        store.save_finding(repo_id, scan_result.scan_id, finding)

    # 6. Update Check Run
    complete_check_run(
        client=gh_client,
        owner=owner,
        repo=repo_name,
        check_run_id=check_run_id,
        conclusion=scan_result.conclusion,
        summary=scan_result.summary,
        findings=scan_result.findings,
    )

    # 7. Post PR review comments
    publish_pull_request_review(
        client=gh_client,
        owner=owner,
        repo=repo_name,
        pull_number=pr_number,
        commit_sha=commit_sha,
        findings=scan_result.findings,
        summary=scan_result.summary,
        max_inline_comments=settings.max_inline_comments,
    )

    logger.info(
        "Completed audit for %s/%s PR #%d: conclusion=%s, findings=%d",
        owner,
        repo_name,
        pr_number,
        scan_result.conclusion.value,
        len(scan_result.findings),
    )
