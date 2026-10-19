"""Unit tests for configuration scanner."""

from sentinelpr.models import FindingCategory, Severity
from sentinelpr.scanners.configuration import ConfigurationScanner


def test_detect_verify_false():
    scanner = ConfigurationScanner()
    diff = """diff --git a/client.py b/client.py
--- a/client.py
+++ b/client.py
@@ -1,3 +1,4 @@
 import requests
+res = requests.get("https://internal.service", verify=False)
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.CRYPTO
    assert f.severity == Severity.HIGH
    assert "TLS" in f.title


def test_detect_debug_true():
    scanner = ConfigurationScanner()
    diff = """diff --git a/settings.py b/settings.py
--- a/settings.py
+++ b/settings.py
@@ -1,2 +1,3 @@
+DEBUG = True
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_clean_config_returns_empty():
    scanner = ConfigurationScanner()
    diff = """diff --git a/settings.py b/settings.py
--- a/settings.py
+++ b/settings.py
@@ -1,2 +1,3 @@
+DEBUG = False
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0
