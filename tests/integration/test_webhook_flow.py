"""Integration test of end-to-end webhook ingestion to worker pipeline."""

import hashlib
import hmac
import json

import boto3
import httpx
import respx
from moto import mock_aws

from sentinelpr.config import Settings
from sentinelpr.handlers import webhook, worker


def _compute_sig(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


@mock_aws
@respx.mock
def test_full_webhook_to_worker_pipeline(monkeypatch):
    # 1. Setup mock AWS infrastructure
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="sentinelpr-integ",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    sqs = boto3.client("sqs", region_name="us-east-1")
    q = sqs.create_queue(QueueName="sentinelpr-scan-queue-integ")
    queue_url = q["QueueUrl"]

    settings = Settings(
        ENVIRONMENT="integ",
        GITHUB_WEBHOOK_SECRET="integ_webhook_secret_key",
        DYNAMODB_TABLE_NAME="sentinelpr-integ",
        SCAN_QUEUE_URL=queue_url,
        ALLOWED_REPO_IDS="123456789",
        GITHUB_APP_ID=9999,
        GITHUB_APP_PRIVATE_KEY_PEM="fake_pem",
    )
    monkeypatch.setattr(webhook, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "get_private_key_pem", lambda s: "dummy_pem")
    monkeypatch.setattr(
        worker.GitHubAppAuth, "get_installation_token", lambda self, iid: "fake_token"
    )

    # 2. Mock GitHub API
    respx.post("https://api.github.com/repos/example-org/cad_project/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 5001})
    )
    respx.get("https://api.github.com/repos/example-org/cad_project/pulls/42").mock(
        return_value=httpx.Response(200, text="diff --git a/app.py b/app.py\n+import os\n")
    )
    respx.patch("https://api.github.com/repos/example-org/cad_project/check-runs/5001").mock(
        return_value=httpx.Response(200, json={"id": 5001, "status": "completed"})
    )
    respx.post("https://api.github.com/repos/example-org/cad_project/pulls/42/reviews").mock(
        return_value=httpx.Response(200, json={"id": 6001})
    )

    # 3. Ingestion: Receive webhook
    payload = {
        "action": "opened",
        "pull_request": {"number": 42, "head": {"sha": "c0ffee1234567890c0ffee1234567890c0ffee12"}},
        "repository": {"id": 123456789, "name": "cad_project", "owner": {"login": "example-org"}},
        "installation": {"id": 888},
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = _compute_sig("integ_webhook_secret_key", raw_body)

    ingest_event = {
        "body": raw_body.decode("utf-8"),
        "headers": {
            "x-hub-signature-256": sig,
            "x-github-delivery": "delivery-integ-1",
            "x-github-event": "pull_request",
        },
    }

    ingest_resp = webhook.handler(ingest_event, None)
    assert ingest_resp["statusCode"] == 202

    # 4. Worker: Consume from SQS
    messages = sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
    assert len(messages) == 1
    sqs_msg = messages[0]

    worker_event = {
        "Records": [
            {
                "messageId": sqs_msg["MessageId"],
                "body": sqs_msg["Body"],
            }
        ]
    }

    worker_resp = worker.handler(worker_event, None)
    assert worker_resp == {"batchItemFailures": []}
