"""Unit tests for DynamoDB single table persistence."""

import boto3
import pytest
from moto import mock_aws

from sentinelpr.models import (
    CheckConclusion,
    Finding,
    FindingCategory,
    ScanResult,
    ScanStatus,
    Severity,
)
from sentinelpr.storage.dynamodb import DynamoDBStore


@pytest.fixture
def mock_dynamodb_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
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
        yield client


def test_delivery_deduplication(mock_dynamodb_table):
    store = DynamoDBStore(table_name="sentinelpr-test", client=mock_dynamodb_table)

    # First attempt should register delivery ID successfully
    assert store.record_delivery_if_new("delivery-uuid-1") is True

    # Second attempt with same ID should detect duplicate
    assert store.record_delivery_if_new("delivery-uuid-1") is False

    # Different ID should succeed
    assert store.record_delivery_if_new("delivery-uuid-2") is True


def test_save_and_get_scan_job(mock_dynamodb_table):
    store = DynamoDBStore(table_name="sentinelpr-test", client=mock_dynamodb_table)

    scan_result = ScanResult(
        scan_id="scan-xyz",
        repo_id="12345",
        status=ScanStatus.SUCCESS,
        conclusion=CheckConclusion.SUCCESS,
        summary="Clean PR",
    )

    store.save_scan_job(scan_result)
    retrieved = store.get_scan_job("12345", "scan-xyz")

    assert retrieved is not None
    assert retrieved["scan_id"] == "scan-xyz"
    assert retrieved["status"] == "SUCCESS"
    assert retrieved["conclusion"] == "success"


def test_save_finding_stores_no_plaintext_secret(mock_dynamodb_table):
    store = DynamoDBStore(table_name="sentinelpr-test", client=mock_dynamodb_table)

    finding = Finding(
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        title="Detected API Key",
        description="Key exposed",
        file_path="secrets.py",
        line_start=1,
        line_end=1,
        evidence="[REDACTED_SECRET_8a7c29e1]",
        is_secret=True,
    )

    store.save_finding(repo_id="12345", scan_id="scan-xyz", finding=finding)

    # Directly inspect item in DynamoDB
    resp = mock_dynamodb_table.get_item(
        TableName="sentinelpr-test",
        Key={
            "PK": {"S": "REPO#12345"},
            "SK": {"S": f"SCAN#scan-xyz#FINDING#{finding.fingerprint}"},
        },
    )
    item = resp.get("Item")
    assert item is not None
    assert item["is_secret"]["BOOL"] is True
    assert "[REDACTED_SECRET_" in item["evidence"]["S"]
