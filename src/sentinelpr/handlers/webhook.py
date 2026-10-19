"""AWS Lambda Ingestion Handler for GitHub Webhooks."""

from __future__ import annotations

import base64
import json
from typing import Any

import boto3

from sentinelpr.config import get_settings
from sentinelpr.logging_utils import get_logger
from sentinelpr.security.signature import SignatureVerificationError, verify_github_signature
from sentinelpr.storage.dynamodb import DynamoDBStore

logger = get_logger("sentinelpr.webhook")


def get_secret_from_secrets_manager(secret_arn: str) -> str:
    """Retrieves secret string from AWS Secrets Manager."""
    sm = boto3.client("secretsmanager")
    res = sm.get_secret_value(SecretId=secret_arn)
    return res.get("SecretString", "")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """API Gateway HTTP API Lambda handler for GitHub webhooks."""
    settings = get_settings()

    # 1. Extract raw body bytes
    raw_body_str = event.get("body", "")
    if event.get("isBase64Encoded", False):
        raw_body = base64.b64decode(raw_body_str)
    else:
        raw_body = raw_body_str.encode("utf-8") if isinstance(raw_body_str, str) else raw_body_str

    # 2. Extract GitHub headers (case-insensitive)
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    signature = headers.get("x-hub-signature-256")
    delivery_id = headers.get("x-github-delivery")
    github_event = headers.get("x-github-event")

    # 3. Retrieve webhook secret
    webhook_secret = settings.github_webhook_secret
    if not webhook_secret and settings.github_webhook_secret_arn:
        try:
            webhook_secret = get_secret_from_secrets_manager(settings.github_webhook_secret_arn)
        except Exception as e:
            logger.error("Failed fetching webhook secret from Secrets Manager: %s", e)
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "Internal secret resolution error"}),
            }

    if not webhook_secret:
        logger.error("Webhook secret is unconfigured")
        return {"statusCode": 500, "body": json.dumps({"error": "Webhook secret unconfigured"})}

    # 4. Verify HMAC-SHA256 signature
    try:
        verify_github_signature(raw_body, webhook_secret, signature)
    except SignatureVerificationError as e:
        logger.warning("Signature verification rejected: %s", e)
        return {"statusCode": 401, "body": json.dumps({"error": "Invalid webhook signature"})}

    # 5. Parse JSON payload safely
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        logger.error("JSON parsing error on signature-valid webhook: %s", e)
        # Return 202 so an attacker cannot probe internal parser errors
        return {"statusCode": 202, "body": json.dumps({"status": "acknowledged"})}

    # 6. Filter supported events and actions
    action = payload.get("action", "")
    is_pr_event = github_event == "pull_request" and action in ("opened", "reopened", "synchronize")
    is_check_rerun = github_event == "check_suite" and action in ("rerequested",)

    if not (is_pr_event or is_check_rerun):
        logger.info("Ignoring unsupported event: %s action: %s", github_event, action)
        return {
            "statusCode": 200,
            "body": json.dumps({"status": "ignored", "reason": "unsupported event"}),
        }

    # 7. Validate repository allowlist
    repo_data = payload.get("repository", {})
    repo_id = repo_data.get("id")
    if not repo_id or not settings.is_repo_allowed(repo_id):
        logger.warning("Repository %s is not in allowlist", repo_id)
        return {
            "statusCode": 200,
            "body": json.dumps({"status": "ignored", "reason": "repo not allowed"}),
        }

    # 8. Deduplicate delivery ID in DynamoDB
    store = DynamoDBStore(table_name=settings.dynamodb_table_name)
    if delivery_id:
        is_new = store.record_delivery_if_new(delivery_id)
        if not is_new:
            logger.info("Deduplicated repeated delivery ID: %s", delivery_id)
            return {"statusCode": 200, "body": json.dumps({"status": "duplicate delivery skipped"})}

    # 9. Queue accepted scan job to SQS
    if settings.scan_queue_url:
        sqs = boto3.client("sqs")
        job_message = {
            "delivery_id": delivery_id,
            "event": github_event,
            "action": action,
            "repository": {
                "id": repo_id,
                "name": repo_data.get("name"),
                "full_name": repo_data.get("full_name"),
                "owner": repo_data.get("owner", {}).get("login"),
            },
            "pull_request": {
                "number": payload.get("pull_request", {}).get("number")
                or (
                    payload.get("check_suite", {}).get("pull_requests", [{}])[0].get("number")
                    if is_check_rerun
                    else None
                ),
                "head_sha": payload.get("pull_request", {}).get("head", {}).get("sha")
                or payload.get("check_suite", {}).get("head_sha"),
            },
            "installation": {
                "id": payload.get("installation", {}).get("id"),
            },
        }

        try:
            sqs.send_message(
                QueueUrl=settings.scan_queue_url,
                MessageBody=json.dumps(job_message),
            )
            logger.info("Scan job dispatched to SQS for delivery ID %s", delivery_id)
        except Exception as e:
            logger.error("Failed enqueuing job to SQS: %s", e)
            return {"statusCode": 500, "body": json.dumps({"error": "Failed dispatching job"})}

    return {
        "statusCode": 202,
        "body": json.dumps({"status": "accepted", "delivery_id": delivery_id}),
    }
