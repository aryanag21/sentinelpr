"""Unit tests for the webhook ingestion Lambda handler."""

import hashlib
import hmac
import json

import boto3
import pytest
from moto import mock_aws

from sentinelpr.config import Settings
from sentinelpr.handlers import webhook


def _compute_sig(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


@pytest.fixture
def mock_aws_env(monkeypatch):
    with mock_aws():
        # Setup DynamoDB
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="sentinelpr-test",
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

        # Setup SQS
        sqs = boto3.client("sqs", region_name="us-east-1")
        q = sqs.create_queue(QueueName="test-queue")
        queue_url = q["QueueUrl"]

        # Override settings
        test_settings = Settings(
            ENVIRONMENT="test",
            GITHUB_WEBHOOK_SECRET="test_webhook_secret_key",
            DYNAMODB_TABLE_NAME="sentinelpr-test",
            SCAN_QUEUE_URL=queue_url,
            ALLOWED_REPO_IDS="123456789",
        )
        monkeypatch.setattr(webhook, "get_settings", lambda: test_settings)

        yield {"dynamodb": ddb, "sqs": sqs, "queue_url": queue_url}


def test_valid_webhook_event_accepted(mock_aws_env):
    payload = {
        "action": "opened",
        "pull_request": {"number": 1, "head": {"sha": "abc1234"}},
        "repository": {"id": 123456789, "name": "cad_project", "owner": {"login": "org"}},
        "installation": {"id": 555},
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = _compute_sig("test_webhook_secret_key", raw_body)

    event = {
        "body": raw_body.decode("utf-8"),
        "isBase64Encoded": False,
        "headers": {
            "x-hub-signature-256": sig,
            "x-github-delivery": "delivery-123",
            "x-github-event": "pull_request",
        },
    }

    res = webhook.handler(event, None)
    assert res["statusCode"] == 202
    assert "accepted" in res["body"]

    # Verify message queued to SQS
    sqs = mock_aws_env["sqs"]
    msgs = sqs.receive_message(QueueUrl=mock_aws_env["queue_url"]).get("Messages", [])
    assert len(msgs) == 1


def test_invalid_signature_returns_401(mock_aws_env):
    event = {
        "body": '{"action":"opened"}',
        "headers": {
            "x-hub-signature-256": "sha256=invalid0000000000000000000000000000000000000000000000000000000000",
            "x-github-delivery": "delivery-123",
            "x-github-event": "pull_request",
        },
    }
    res = webhook.handler(event, None)
    assert res["statusCode"] == 401


def test_duplicate_delivery_deduplicated(mock_aws_env):
    payload = {
        "action": "opened",
        "pull_request": {"number": 1},
        "repository": {"id": 123456789},
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = _compute_sig("test_webhook_secret_key", raw_body)

    event = {
        "body": raw_body.decode("utf-8"),
        "headers": {
            "x-hub-signature-256": sig,
            "x-github-delivery": "delivery-duplicate-test",
            "x-github-event": "pull_request",
        },
    }

    # First request: accepted
    r1 = webhook.handler(event, None)
    assert r1["statusCode"] == 202

    # Second request with same delivery ID: skipped as duplicate
    r2 = webhook.handler(event, None)
    assert r2["statusCode"] == 200
    assert "duplicate" in r2["body"]


def test_unsupported_event_ignored(mock_aws_env):
    raw_body = b'{"action":"closed"}'
    sig = _compute_sig("test_webhook_secret_key", raw_body)
    event = {
        "body": raw_body.decode("utf-8"),
        "headers": {
            "x-hub-signature-256": sig,
            "x-github-delivery": "delivery-ignored",
            "x-github-event": "issues",
        },
    }
    res = webhook.handler(event, None)
    assert res["statusCode"] == 200
    assert "ignored" in res["body"]
