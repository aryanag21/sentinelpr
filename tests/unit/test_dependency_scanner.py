"""Unit tests for dependency vulnerability scanning."""

from sentinelpr.models import FindingCategory, Severity
from sentinelpr.scanners.dependencies import DependencyScanner


def test_detect_vulnerable_dependency_in_diff():
    scanner = DependencyScanner(offline=True)
    diff = """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
+requests==2.25.0
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.DEPENDENCY
    assert f.severity == Severity.HIGH
    assert "requests==2.25.0" in f.title


def test_clean_dependency_in_diff():
    scanner = DependencyScanner(offline=True)
    diff = """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
+requests==2.31.0
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0


def test_non_dependency_diff_returns_empty():
    scanner = DependencyScanner(offline=True)
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
+print("hello")
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0
