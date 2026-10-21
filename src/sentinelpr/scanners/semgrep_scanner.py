"""Static Application Security Testing (SAST) scanner using Semgrep with fallback."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentinelpr.models import Finding, FindingCategory
from sentinelpr.scanners.base import BaseScanner, is_ignored_path
from sentinelpr.security.policy import normalize_scanner_finding


class SemgrepScanner(BaseScanner):
    """Detects injection, unsafe subprocess, deserialization, and dangerous patterns."""

    name: str = "semgrep"

    def __init__(self, rules_path: str = "infrastructure/semgrep-rules"):
        self.rules_path = rules_path
        self.semgrep_bin = shutil.which("semgrep") or "semgrep"

    def _is_semgrep_available(self) -> bool:
        if not shutil.which(self.semgrep_bin):
            return False
        try:
            res = subprocess.run(
                [self.semgrep_bin, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def scan_path(self, path: str, **kwargs: Any) -> list[Finding]:
        """Runs Semgrep against a directory or file path."""
        findings: list[Finding] = []
        if self._is_semgrep_available() and os.path.exists(self.rules_path):
            findings.extend(self._run_semgrep(path))

        # Complement with builtin SAST patterns to maximize coverage
        builtin_findings = self._run_builtin_sast(path)
        seen = {(f.file_path, f.line_start, f.category) for f in findings}
        for bf in builtin_findings:
            if (bf.file_path, bf.line_start, bf.category) not in seen:
                findings.append(bf)

        return findings

    def scan_diff(self, diff_content: str, **kwargs: Any) -> list[Finding]:
        """Scans changed code in a unified diff."""
        if not diff_content.strip():
            return []

        # If semgrep is available, we can write modified files to a temp tree or run fallback
        return self._run_builtin_diff_sast(diff_content)

    def _run_semgrep(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        cmd = [
            self.semgrep_bin,
            "scan",
            "--config",
            self.rules_path,
            "--json",
            "--no-rewrite-rule-ids",
            "--quiet",
            "--metrics=off",
            target,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.stdout:
                data = json.loads(proc.stdout)
                for item in data.get("results", []):
                    findings.append(self._parse_semgrep_result(item))
        except Exception:
            # Fall back to builtin
            return self._run_builtin_sast(target)

        return findings

    def _parse_semgrep_result(self, item: dict[str, Any]) -> Finding:
        check_id = item.get("check_id", "semgrep-rule")
        extra = item.get("extra", {})
        message = extra.get("message", "Security issue detected by Semgrep")
        raw_sev = extra.get("severity", "WARNING").upper()
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", "")
        category = FindingCategory.OTHER

        cwe_str = str(cwe).lower()
        if "89" in cwe_str or "sql" in check_id.lower():
            category = FindingCategory.INJECTION
            display_title = f"Semgrep SQL Injection: {check_id}"
        elif "78" in cwe_str or "command" in check_id.lower() or "subprocess" in check_id.lower():
            category = FindingCategory.INJECTION
            display_title = f"Semgrep Command Injection: {check_id}"
        elif "502" in cwe_str or "pickle" in check_id.lower():
            category = FindingCategory.DESERIALIZATION
            display_title = f"Semgrep Insecure Deserialization: {check_id}"
        elif "22" in cwe_str or "traversal" in check_id.lower():
            category = FindingCategory.PATH_TRAVERSAL
            display_title = f"Semgrep Path Traversal: {check_id}"
        else:
            display_title = f"Semgrep: {check_id}"

        path = item.get("path", "unknown")
        start = item.get("start", {}).get("line", 1)
        end = item.get("end", {}).get("line", start)
        lines = extra.get("lines", "").strip()

        return normalize_scanner_finding(
            raw_source=self.name,
            raw_severity=raw_sev,
            title=display_title,
            description=message,
            file_path=path,
            line_start=start,
            line_end=end,
            evidence=lines[:300],
            category=category,
            confidence="HIGH",
            remediation="Sanitize input or use parameterized queries/safe APIs.",
            rule_id=check_id,
            is_secret=False,
        )

    def _run_builtin_sast(self, target_path: str) -> list[Finding]:
        """Built-in SAST pattern analyzer for Python & JS/TS."""
        findings: list[Finding] = []
        p = Path(target_path)
        if p.is_file():
            files = [p]
        else:
            files = [
                f
                for f in p.rglob("*")
                if f.is_file()
                and not is_ignored_path(f)
                and f.name != "semgrep_scanner.py"
                and not (any(part in ("unit", "integration") for part in f.parts))
                and f.suffix in (".py", ".js", ".ts", ".jsx", ".tsx")
            ]

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self._analyze_code_string(content, str(f)))
            except Exception:
                continue
        return findings

    def _run_builtin_diff_sast(self, diff_content: str) -> list[Finding]:
        findings: list[Finding] = []
        current_file = "unknown"
        current_line = 0

        for line in diff_content.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            if line.startswith("@@ "):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
                continue
            if line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                code_line = line[1:]
                for finding in self._check_code_line(code_line, current_file, current_line):
                    findings.append(finding)
            elif not line.startswith("-"):
                current_line += 1

        return findings

    def _analyze_code_string(self, content: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            findings.extend(self._check_code_line(line, file_path, idx))
        return findings

    def _check_code_line(self, line: str, file_path: str, line_no: int) -> list[Finding]:
        results: list[Finding] = []
        trimmed = line.strip()

        # 1. SQL Injection pattern
        if re.search(
            r"""(?i)(?:select|insert|update|delete)\s+.*?\s+(?:from|into|set)\s+.*?['"].*?(?:%s|\+|\{.*?\}|format\()""",
            trimmed,
        ):
            if (
                "query" in trimmed.lower()
                or "execute" in trimmed.lower()
                or "sql" in trimmed.lower()
            ):
                results.append(
                    normalize_scanner_finding(
                        raw_source=self.name,
                        raw_severity="ERROR",
                        title="SQL Injection Risk: String formatted query",
                        description="Direct interpolation of variables into SQL queries can enable SQL injection.",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        evidence=trimmed[:150],
                        category=FindingCategory.INJECTION,
                        confidence="HIGH",
                        remediation="Use parameterized queries or ORM query builders instead of string formatting.",
                        rule_id="python.lang.security.audit.sqli",
                    )
                )

        # 2. Unsafe subprocess pattern: shell=True with variables
        if "subprocess." in trimmed and "shell=True" in trimmed:
            results.append(
                normalize_scanner_finding(
                    raw_source=self.name,
                    raw_severity="ERROR",
                    title="Command Injection Risk: Subprocess with shell=True",
                    description="Invoking subprocess with shell=True enables shell injection if arguments contain user input.",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    evidence=trimmed[:150],
                    category=FindingCategory.INJECTION,
                    confidence="HIGH",
                    remediation="Avoid shell=True. Pass arguments as a list of strings directly to the executable.",
                    rule_id="python.lang.security.audit.subprocess-shell-true",
                )
            )

        # 3. Unsafe Deserialization: pickle.loads
        if "pickle.loads(" in trimmed or "pickle.load(" in trimmed:
            results.append(
                normalize_scanner_finding(
                    raw_source=self.name,
                    raw_severity="ERROR",
                    title="Insecure Deserialization: Unsafe pickle load",
                    description="Deserializing untrusted data with pickle can lead to arbitrary code execution.",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    evidence=trimmed[:150],
                    category=FindingCategory.DESERIALIZATION,
                    confidence="HIGH",
                    remediation="Use safe serialization formats like JSON, protocol buffers, or cryptographic signing.",
                    rule_id="python.lang.security.audit.insecure-pickle",
                )
            )

        return results
