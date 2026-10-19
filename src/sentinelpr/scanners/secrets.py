"""Deterministic secret scanner integrating Gitleaks with Python fallback."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from sentinelpr.models import Finding, FindingCategory
from sentinelpr.scanners.base import BaseScanner
from sentinelpr.security.policy import normalize_scanner_finding
from sentinelpr.security.redaction import _SECRET_PATTERNS, mask_secret


class SecretScanner(BaseScanner):
    """Detects accidentally committed credentials and API keys."""

    name: str = "gitleaks"

    def __init__(self, gitleaks_path: str = "gitleaks", config_path: str = ".gitleaks.toml"):
        self.gitleaks_bin = shutil.which(gitleaks_path) or gitleaks_path
        self.config_path = config_path

    def _is_gitleaks_available(self) -> bool:
        if not shutil.which(self.gitleaks_bin):
            return False
        try:
            res = subprocess.run(
                [self.gitleaks_bin, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def scan_path(self, path: str, full_history: bool = False, **kwargs: Any) -> list[Finding]:
        """Scans a repository directory or file for hardcoded secrets."""
        if self._is_gitleaks_available():
            return self._run_gitleaks_dir(path)
        return self._run_builtin_dir(path)

    def scan_diff(self, diff_content: str, **kwargs: Any) -> list[Finding]:
        """Scans a unified diff string for secrets in added lines."""
        if not diff_content.strip():
            return []

        if self._is_gitleaks_available():
            return self._run_gitleaks_diff(diff_content)
        return self._run_builtin_diff(diff_content)

    def _run_gitleaks_dir(self, source_dir: str) -> list[Finding]:
        findings: list[Finding] = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            cmd = [
                self.gitleaks_bin,
                "detect",
                "--source",
                source_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
            ]
            if os.path.exists(self.config_path):
                cmd.extend(["--config", self.config_path])

            subprocess.run(cmd, capture_output=True, text=True, check=False)

            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, encoding="utf-8") as f:
                    raw_findings = json.load(f)

                for item in raw_findings:
                    findings.append(self._parse_gitleaks_item(item))
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

        return findings

    def _run_gitleaks_diff(self, diff_content: str) -> list[Finding]:
        findings: list[Finding] = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            cmd = [
                self.gitleaks_bin,
                "detect",
                "--pipe",
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
            ]
            if os.path.exists(self.config_path):
                cmd.extend(["--config", self.config_path])

            subprocess.run(
                cmd,
                input=diff_content,
                capture_output=True,
                text=True,
                check=False,
            )

            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, encoding="utf-8") as f:
                    raw_findings = json.load(f)

                for item in raw_findings:
                    findings.append(self._parse_gitleaks_item(item))
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

        return findings

    def _parse_gitleaks_item(self, item: dict[str, Any]) -> Finding:
        # Strictly mask the raw secret immediately
        raw_secret = item.get("Secret", "")
        masked_val = mask_secret(raw_secret)
        file_path = item.get("File", "unknown")
        line_start = item.get("StartLine", 1)
        line_end = item.get("EndLine", line_start)
        rule_id = item.get("RuleID", "gitleaks-secret")
        desc = item.get("Description", "Exposed Secret")

        return normalize_scanner_finding(
            raw_source=self.name,
            raw_severity="CRITICAL",
            title=f"Detected {desc} ({rule_id})",
            description=f"Secret identified by rule '{rule_id}'. Value has been masked for safety.",
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            evidence=f"Secret value masked: {masked_val}",
            category=FindingCategory.SECRETS,
            confidence="HIGH",
            remediation="Revoke and rotate this credential immediately. Removing it from the file does not purge Git history.",
            rule_id=rule_id,
            is_secret=True,
        )

    def _run_builtin_dir(self, source_dir: str) -> list[Finding]:
        """Built-in deterministic scanner matching .gitleaks.toml patterns directly."""
        findings: list[Finding] = []
        p = Path(source_dir)
        if p.is_file():
            files = [p]
        else:
            files = [
                f
                for f in p.rglob("*")
                if f.is_file()
                and not any(
                    part.startswith(".") or part in ("__pycache__", "node_modules", "dist", "build")
                    for part in f.parts
                )
            ]

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self._scan_lines(content.splitlines(), str(file_path)))
            except Exception:
                continue
        return findings

    def _run_builtin_diff(self, diff_content: str) -> list[Finding]:
        """Scans added lines in a diff using built-in deterministic patterns."""
        findings: list[Finding] = []
        current_file = "unknown"
        current_line = 0

        for line in diff_content.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            if line.startswith("@@ "):
                # Extract starting line number in target file: @@ -x,y +start,len @@
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
                continue
            if line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                added_code = line[1:]
                # Check line for secrets
                for f in self._scan_line(added_code, current_file, current_line):
                    findings.append(f)
            elif not line.startswith("-"):
                current_line += 1

        return findings

    def _scan_lines(self, lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            findings.extend(self._scan_line(line, file_path, idx))
        return findings

    def _scan_line(self, line: str, file_path: str, line_no: int) -> list[Finding]:
        # Respect gitleaks:allow inline suppression
        if "gitleaks:allow" in line:
            return []

        results: list[Finding] = []
        for pattern_name, regex in _SECRET_PATTERNS:
            if pattern_name == "PRIVATE_KEY":
                continue
            for match in regex.finditer(line):
                matched_val = match.group(0)
                # Ignore benign dummy markers
                if any(x in matched_val.upper() for x in ("EXAMPLE", "DUMMY")):
                    continue
                masked = mask_secret(matched_val)
                results.append(
                    normalize_scanner_finding(
                        raw_source=self.name,
                        raw_severity="CRITICAL",
                        title=f"Detected credential: {pattern_name}",
                        description=f"Potential secret exposed matching {pattern_name}.",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        evidence=f"Match: {masked}",
                        category=FindingCategory.SECRETS,
                        confidence="HIGH",
                        remediation="Revoke and rotate this credential immediately. Removing it from the file does not purge Git history.",
                        rule_id=f"builtin-{pattern_name.lower()}",
                        is_secret=True,
                    )
                )
        return results
