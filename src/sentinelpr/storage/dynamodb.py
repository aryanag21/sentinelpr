"""DynamoDB single-table persistence layer for scans, findings, and deduplication."""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from sentinelpr.models import (
    Finding,
    ScanResult,
)

logger = logging.getLogger(__name__)

# TTL durations in seconds
TTL_DELIVERY_SECONDS = 24 * 3600  # 24 hours
TTL_SCAN_SECONDS = 90 * 24 * 3600  # 90 days


class DynamoDBStore:
    """Encapsulates all DynamoDB persistence operations for SentinelPR."""

    def __init__(self, table_name: str, client: Any | None = None):
        self.table_name = table_name
        self.client = client or boto3.client(
            "dynamodb",
            region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )

    def record_delivery_if_new(self, delivery_id: str) -> bool:
        """Attempts to register a webhook delivery ID using a conditional write.

        Returns:
            True if this delivery ID is new.
            False if it has already been processed (duplicate).
        """
        now = int(time.time())
        ttl = now + TTL_DELIVERY_SECONDS

        item = {
            "PK": {"S": f"DELIVERY#{delivery_id}"},
            "SK": {"S": "META"},
            "delivery_id": {"S": delivery_id},
            "received_at": {"S": datetime.now(UTC).isoformat()},
            "ttl": {"N": str(ttl)},
        }

        try:
            self.client.put_item(
                TableName=self.table_name,
                Item=item,
                ConditionExpression="attribute_not_exists(PK)",
            )
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info("Duplicate delivery detected for ID: %s", delivery_id)
                return False
            raise

    def save_scan_job(self, scan_result: ScanResult) -> None:
        """Persists or updates scan job status."""
        now = int(time.time())
        ttl = now + TTL_SCAN_SECONDS

        item: dict[str, Any] = {
            "PK": {"S": f"REPO#{scan_result.repo_id}"},
            "SK": {"S": f"SCAN#{scan_result.scan_id}"},
            "scan_id": {"S": scan_result.scan_id},
            "repo_id": {"S": scan_result.repo_id},
            "status": {"S": scan_result.status.value},
            "conclusion": {"S": scan_result.conclusion.value},
            "created_at": {"S": scan_result.created_at},
            "updated_at": {"S": scan_result.updated_at},
            "summary": {"S": scan_result.summary[:2000]},
            "scanners_run": {"SS": scan_result.scanners_run or ["none"]},
            "scanners_failed": {"SS": scan_result.scanners_failed or ["none"]},
            "ttl": {"N": str(ttl)},
        }
        if scan_result.pr_number is not None:
            item["pr_number"] = {"N": str(scan_result.pr_number)}
        if scan_result.commit_sha:
            item["commit_sha"] = {"S": scan_result.commit_sha}

        self.client.put_item(TableName=self.table_name, Item=item)

    def save_finding(self, repo_id: str, scan_id: str, finding: Finding) -> None:
        """Persists a normalized security finding. Never saves raw secret values."""
        now = int(time.time())
        ttl = now + TTL_SCAN_SECONDS

        item: dict[str, Any] = {
            "PK": {"S": f"REPO#{repo_id}"},
            "SK": {"S": f"SCAN#{scan_id}#FINDING#{finding.fingerprint}"},
            "scan_id": {"S": scan_id},
            "fingerprint": {"S": finding.fingerprint},
            "category": {"S": finding.category.value},
            "severity": {"S": finding.severity.value},
            "title": {"S": finding.title[:200]},
            "description": {"S": finding.description[:1000]},
            "file_path": {"S": finding.file_path},
            "line_start": {"N": str(finding.line_start)},
            "line_end": {"N": str(finding.line_end)},
            "evidence": {"S": finding.evidence[:500]},
            "confidence": {"S": finding.confidence},
            "remediation": {"S": finding.remediation[:1000]},
            "source": {"S": finding.source},
            "is_secret": {"BOOL": finding.is_secret},
            "ttl": {"N": str(ttl)},
        }
        if finding.rule_id:
            item["rule_id"] = {"S": finding.rule_id}

        self.client.put_item(TableName=self.table_name, Item=item)

    def get_scan_job(self, repo_id: str, scan_id: str) -> dict[str, Any] | None:
        """Retrieves scan job metadata."""
        resp = self.client.get_item(
            TableName=self.table_name,
            Key={
                "PK": {"S": f"REPO#{repo_id}"},
                "SK": {"S": f"SCAN#{scan_id}"},
            },
        )
        item = resp.get("Item")
        if not item:
            return None

        return {
            "scan_id": item["scan_id"]["S"],
            "repo_id": item["repo_id"]["S"],
            "status": item["status"]["S"],
            "conclusion": item["conclusion"]["S"],
            "summary": item.get("summary", {}).get("S", ""),
        }
