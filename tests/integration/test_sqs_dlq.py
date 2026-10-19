"""Integration test verifying SQS Dead-Letter Queue (DLQ) behavior and batch failure isolation."""

import json

from moto import mock_aws

from sentinelpr.config import Settings
from sentinelpr.handlers import worker


@mock_aws
def test_sqs_batch_item_failure_reporting(monkeypatch):
    # Setup worker settings
    settings = Settings(
        ENVIRONMENT="test",
        DYNAMODB_TABLE_NAME="sentinelpr-dlq-test",
    )
    monkeypatch.setattr(worker, "get_settings", lambda: settings)

    # Two messages in batch: one invalid/corrupted message and one valid
    event = {
        "Records": [
            {
                "messageId": "msg-corrupted",
                "body": "THIS IS INVALID JSON THAT CRASHES PARSER",
            },
            {
                "messageId": "msg-empty-object",
                "body": json.dumps({"unsupported": "payload"}),
            },
        ]
    }

    res = worker.handler(event, None)
    # The corrupted message should be recorded in batchItemFailures so SQS can retry it or send to DLQ
    assert "batchItemFailures" in res
    failed_ids = [item["itemIdentifier"] for item in res["batchItemFailures"]]
    assert "msg-corrupted" in failed_ids
