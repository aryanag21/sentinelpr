"""Unit tests for the secret scanner (Gitleaks integration & builtin fallback)."""

from sentinelpr.models import FindingCategory, Severity
from sentinelpr.scanners.secrets import SecretScanner


def test_detect_secrets_in_diff_masks_values():
    scanner = SecretScanner()
    raw_secret = "sk_live_51ABCDEF1234567890abcdef1234567890"
    diff = f"""diff --git a/app/config.py b/app/config.py
--- a/app/config.py
+++ b/app/config.py
@@ -1,3 +1,4 @@
 import os
+STRIPE_KEY = "{raw_secret}"
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) >= 1
    f = findings[0]

    assert f.category == FindingCategory.SECRETS
    assert f.severity == Severity.CRITICAL
    assert f.is_secret is True
    # Ensure plaintext secret is NEVER contained in the finding output
    assert raw_secret not in f.evidence
    assert raw_secret not in f.description
    assert "[REDACTED_SECRET_" in f.evidence
    assert f.line_start == 2


def test_gitleaks_allow_suppresses_synthetic_finding():
    scanner = SecretScanner()
    diff = """diff --git a/app/config.py b/app/config.py
--- a/app/config.py
+++ b/app/config.py
@@ -1,2 +1,3 @@
+STRIPE_KEY = "sk_live_51ABCDEF1234567890abcdef1234567890"  # gitleaks:allow
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0


def test_clean_diff_returns_no_findings():
    scanner = SecretScanner()
    diff = """diff --git a/app/math.py b/app/math.py
--- a/app/math.py
+++ b/app/math.py
@@ -1,2 +1,3 @@
+def add(a, b):
+    return a + b
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0
