"""Unit tests for policy evaluation and finding normalization."""

from sentinelpr.models import CheckConclusion
from sentinelpr.security.policy import (
    deduplicate_findings,
    evaluate_policy,
    normalize_scanner_finding,
)


def test_confirmed_secret_triggers_failure():
    f = normalize_scanner_finding(
        raw_source="gitleaks",
        raw_severity="CRITICAL",
        title="Detected Stripe Key",
        description="Key found",
        file_path="secrets.py",
        line_start=1,
        line_end=1,
        evidence="[REDACTED_SECRET_123]",
        is_secret=True,
    )
    conclusion, summary = evaluate_policy([f])
    assert conclusion == CheckConclusion.FAILURE
    assert "Critical Action Required" in summary


def test_deterministic_high_triggers_failure():
    f = normalize_scanner_finding(
        raw_source="semgrep",
        raw_severity="ERROR",
        title="SQL Injection",
        description="SQLi detected",
        file_path="sqli.py",
        line_start=5,
        line_end=5,
        evidence="db.execute(...)",
    )
    conclusion, summary = evaluate_policy([f])
    assert conclusion == CheckConclusion.FAILURE
    assert "High-Priority Vulnerabilities" in summary


def test_deterministic_medium_triggers_neutral():
    f = normalize_scanner_finding(
        raw_source="semgrep",
        raw_severity="WARNING",
        title="Weak Cipher",
        description="Deprecated cipher",
        file_path="tls.py",
        line_start=10,
        line_end=10,
        evidence="ssl.PROTOCOL_SSLv3",
    )
    conclusion, summary = evaluate_policy([f])
    assert conclusion == CheckConclusion.NEUTRAL


def test_ai_only_high_does_not_block():
    f = normalize_scanner_finding(
        raw_source="bedrock",
        raw_severity="HIGH",
        title="Contextual Business Logic Bug",
        description="Logic flaw detected by AI",
        file_path="logic.py",
        line_start=20,
        line_end=20,
        evidence="if role == 'user': grant_admin()",
        confidence="HIGH",
    )
    conclusion, summary = evaluate_policy([f])
    # AI-only finding should NOT fail the check by default, but trigger neutral warning
    assert conclusion == CheckConclusion.NEUTRAL


def test_warn_only_mode_downgrades_failure():
    f = normalize_scanner_finding(
        raw_source="gitleaks",
        raw_severity="CRITICAL",
        title="Secret Key",
        description="API Key found",
        file_path="conf.py",
        line_start=1,
        line_end=1,
        evidence="[REDACTED]",
        is_secret=True,
    )
    conclusion, summary = evaluate_policy([f], warn_only_mode=True)
    assert conclusion == CheckConclusion.NEUTRAL


def test_clean_findings_triggers_success():
    conclusion, summary = evaluate_policy([])
    assert conclusion == CheckConclusion.SUCCESS
    assert "**Total findings:** 0" in summary


def test_deduplicate_findings_preserves_unique():
    f1 = normalize_scanner_finding(
        raw_source="semgrep",
        raw_severity="ERROR",
        title="SQLi",
        description="desc",
        file_path="a.py",
        line_start=1,
        line_end=1,
        evidence="code1",
    )
    f2 = normalize_scanner_finding(
        raw_source="semgrep",
        raw_severity="ERROR",
        title="SQLi",
        description="desc",
        file_path="a.py",
        line_start=1,
        line_end=1,
        evidence="code1",
    )
    unique = deduplicate_findings([f1, f2])
    assert len(unique) == 1
