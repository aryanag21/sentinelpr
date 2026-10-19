"""Configuration and insecure default checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sentinelpr.models import Finding, FindingCategory
from sentinelpr.scanners.base import BaseScanner, is_ignored_path
from sentinelpr.security.policy import normalize_scanner_finding

_CONFIG_RULES: list[dict[str, Any]] = [
    {
        "id": "config.insecure-tls-verify-disabled",
        "title": "Disabled TLS Certificate Validation",
        "regex": re.compile(r"""(?i)\bverify\s*=\s*(?:False|0)\b"""),
        "severity": "HIGH",
        "category": FindingCategory.CRYPTO,
        "description": "Disabling TLS certificate verification allows Man-In-The-Middle (MITM) attacks.",
        "remediation": "Remove verify=False or provide a trusted CA bundle.",
    },
    {
        "id": "config.debug-mode-enabled",
        "title": "Debug Mode Enabled in Configuration",
        "regex": re.compile(r"""(?i)\b(?:DEBUG|debug)\s*=\s*True\b"""),
        "severity": "MEDIUM",
        "category": FindingCategory.CONFIG,
        "description": "Running web frameworks with debug enabled exposes interactive tracebacks and secrets.",
        "remediation": "Ensure debug mode is disabled or configured exclusively via environment variables.",
    },
    {
        "id": "config.permissive-cors-wildcard",
        "title": "Overly Permissive CORS Configuration",
        "regex": re.compile(
            r"""(?i)allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|access-control-allow-origin\s*:\s*\*"""
        ),
        "severity": "MEDIUM",
        "category": FindingCategory.CONFIG,
        "description": "Wildcard CORS origin ('*') allows arbitrary third-party websites to make cross-origin requests.",
        "remediation": "Restrict allowed origins to trusted domains.",
    },
    {
        "id": "config.insecure-tls-version",
        "title": "Insecure / Deprecated TLS Version Configured",
        "regex": re.compile(r"""(?i)\b(?:PROTOCOL_TLSv1|PROTOCOL_SSLv23|PROTOCOL_SSLv3)\b"""),
        "severity": "HIGH",
        "category": FindingCategory.CRYPTO,
        "description": "Deprecated TLS/SSL protocol versions are vulnerable to POODLE, BEAST, and other downgrade attacks.",
        "remediation": "Enforce TLS 1.2 or TLS 1.3.",
    },
]


class ConfigurationScanner(BaseScanner):
    """Detects dangerous configurations such as disabled TLS verification or overly permissive CORS."""

    name: str = "config-checker"

    def scan_path(self, path: str, **kwargs: Any) -> list[Finding]:
        findings: list[Finding] = []
        p = Path(path)
        if p.is_file():
            files = [p]
        else:
            files = [
                f
                for f in p.rglob("*")
                if f.is_file()
                and not is_ignored_path(f)
                and f.name != "configuration.py"
                and "semgrep-rules" not in f.parts
                and not (any(part in ("unit", "integration") for part in f.parts))
                and f.suffix
                in (".py", ".json", ".yaml", ".yml", ".env", ".ini", ".conf", ".ts", ".js")
            ]

        for file_path in files:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                findings.extend(self._scan_lines(lines, str(file_path)))
            except Exception:
                continue
        return findings

    def scan_diff(self, diff_content: str, **kwargs: Any) -> list[Finding]:
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
                for rule in _CONFIG_RULES:
                    if rule["regex"].search(code_line):
                        findings.append(
                            normalize_scanner_finding(
                                raw_source=self.name,
                                raw_severity=rule["severity"],
                                title=rule["title"],
                                description=rule["description"],
                                file_path=current_file,
                                line_start=current_line,
                                line_end=current_line,
                                evidence=code_line.strip()[:150],
                                category=rule["category"],
                                confidence="HIGH",
                                remediation=rule["remediation"],
                                rule_id=rule["id"],
                            )
                        )
            elif not line.startswith("-"):
                current_line += 1

        return findings

    def _scan_lines(self, lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            # Ignore comments
            if clean.startswith("#") or clean.startswith("//"):
                continue
            for rule in _CONFIG_RULES:
                if rule["regex"].search(clean):
                    findings.append(
                        normalize_scanner_finding(
                            raw_source=self.name,
                            raw_severity=rule["severity"],
                            title=rule["title"],
                            description=rule["description"],
                            file_path=file_path,
                            line_start=idx,
                            line_end=idx,
                            evidence=clean[:150],
                            category=rule["category"],
                            confidence="HIGH",
                            remediation=rule["remediation"],
                            rule_id=rule["id"],
                        )
                    )
        return findings
