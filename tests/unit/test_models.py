"""Unit tests for SentinelPR data models and schemas."""

from sentinelpr.models import (
    CheckConclusion,
    Finding,
    FindingCategory,
    ScanResult,
    ScanStatus,
    Severity,
)


def test_severity_from_str():
    assert Severity.from_str("CRITICAL") == Severity.CRITICAL
    assert Severity.from_str("blocker") == Severity.CRITICAL
    assert Severity.from_str("ERROR") == Severity.HIGH
    assert Severity.from_str("warning") == Severity.MEDIUM
    assert Severity.from_str("low") == Severity.LOW
    assert Severity.from_str("informational") == Severity.INFO


def test_finding_fingerprint_is_stable_and_deterministic():
    f1 = Finding(
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        title="Test Secret",
        description="Found fake secret",
        file_path="app/config.py",
        line_start=10,
        line_end=10,
        evidence="[REDACTED_SECRET_abc]",
        source="gitleaks",
        rule_id="stripe-api-key",
    )
    f2 = Finding(
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        title="Test Secret",
        description="Different description",
        file_path="app/config.py",
        line_start=10,
        line_end=10,
        evidence="[REDACTED_SECRET_abc]",
        source="gitleaks",
        rule_id="stripe-api-key",
    )

    assert f1.fingerprint == f2.fingerprint
    assert len(f1.fingerprint) == 16


def test_finding_to_dict_and_from_dict():
    f = Finding(
        category=FindingCategory.INJECTION,
        severity=Severity.HIGH,
        title="SQLi detected",
        description="SQL injection in query",
        file_path="db.py",
        line_start=15,
        line_end=17,
        evidence="query = f'SELECT...'",
        source="semgrep",
    )
    d = f.to_dict()
    assert d["category"] == "injection"
    assert d["severity"] == "HIGH"

    restored = Finding.from_dict(d)
    assert restored.category == FindingCategory.INJECTION
    assert restored.severity == Severity.HIGH
    assert restored.fingerprint == f.fingerprint


def test_scan_result_serialization():
    res = ScanResult(
        scan_id="scan-123",
        repo_id="repo-456",
        status=ScanStatus.SUCCESS,
        conclusion=CheckConclusion.SUCCESS,
        summary="Clean scan",
    )
    d = res.to_dict()
    assert d["scan_id"] == "scan-123"
    assert d["status"] == "SUCCESS"
    assert d["conclusion"] == "success"
