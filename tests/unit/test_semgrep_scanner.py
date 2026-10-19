"""Unit tests for Semgrep SAST scanner."""

from sentinelpr.models import FindingCategory, Severity
from sentinelpr.scanners.semgrep_scanner import SemgrepScanner


def test_detect_sqli_in_diff():
    scanner = SemgrepScanner()
    diff = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -10,3 +10,4 @@
 def query_user(user_input):
+    query = f"SELECT * FROM users WHERE name = '{user_input}'"
     return db.execute(query)
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) >= 1
    f = findings[0]
    assert f.category == FindingCategory.INJECTION
    assert f.severity == Severity.HIGH
    assert "SQL" in f.title


def test_detect_subprocess_shell_true_in_diff():
    scanner = SemgrepScanner()
    diff = """diff --git a/app/cmd.py b/app/cmd.py
--- a/app/cmd.py
+++ b/app/cmd.py
@@ -1,3 +1,4 @@
 import subprocess
+def run_tool(cmd):
+    subprocess.run(cmd, shell=True)
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) >= 1
    f = findings[0]
    assert f.category == FindingCategory.INJECTION
    assert "shell=True" in f.title


def test_clean_diff_produces_no_semgrep_findings():
    scanner = SemgrepScanner()
    diff = """diff --git a/app/clean.py b/app/clean.py
--- a/app/clean.py
+++ b/app/clean.py
@@ -1,2 +1,3 @@
 def multiply(x, y):
+    return x * y
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 0
