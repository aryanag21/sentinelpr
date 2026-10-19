"""Unit tests for AI review orchestration and response normalization."""

from unittest.mock import MagicMock

from sentinelpr.ai.analysis import run_ai_security_review
from sentinelpr.ai.bedrock_client import BedrockClient, BedrockError
from sentinelpr.models import FindingCategory, Severity


def test_ai_review_successful_parsing():
    mock_client = MagicMock(spec=BedrockClient)
    mock_client.invoke.return_value = """{
      "findings": [
        {
          "category": "injection",
          "severity": "HIGH",
          "title": "SQL Injection in User Profile Lookup",
          "description": "SQL injection detected in query",
          "file_path": "db.py",
          "line_start": 10,
          "line_end": 12,
          "evidence": "query = f'SELECT...'",
          "confidence": "HIGH",
          "remediation": "Use parameterized queries",
          "source": "ai",
          "rule_id": "ai.sqli"
        }
      ],
      "summary": "Found 1 SQLi"
    }"""

    findings, summary, degraded = run_ai_security_review(
        diff_content="diff --git a/db.py b/db.py\n+query=f'SELECT...'",
        deterministic_findings=[],
        client=mock_client,
    )

    assert not degraded
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.INJECTION
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "bedrock"


def test_ai_review_malformed_json_degrades_cleanly():
    mock_client = MagicMock(spec=BedrockClient)
    mock_client.invoke.return_value = "This is not json at all."

    findings, summary, degraded = run_ai_security_review(
        diff_content="diff --git a/a.py b/a.py\n+code",
        deterministic_findings=[],
        client=mock_client,
    )

    assert degraded is True
    assert len(findings) == 0
    assert "degraded" in summary.lower() or "malformed" in summary.lower()


def test_ai_review_bedrock_error_does_not_crash():
    mock_client = MagicMock(spec=BedrockClient)
    mock_client.invoke.side_effect = BedrockError("API unavailable")

    findings, summary, degraded = run_ai_security_review(
        diff_content="diff --git a/a.py b/a.py\n+code",
        deterministic_findings=[],
        client=mock_client,
    )

    assert degraded is True
    assert len(findings) == 0
    assert "unavailable" in summary.lower()
