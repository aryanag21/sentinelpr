"""Dependency vulnerability scanning using pip-audit and osv-scanner."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentinelpr.models import Finding, FindingCategory
from sentinelpr.scanners.base import BaseScanner, is_ignored_path
from sentinelpr.security.policy import normalize_scanner_finding

# Known vulnerable versions for offline/test environments
_KNOWN_VULNERABLE_PACKAGES: dict[str, dict[str, str]] = {
    "requests": {
        "2.25.0": "CVE-2023-32681 (Unintended leak of Proxy-Authorization header)",
    },
    "urllib3": {
        "1.26.4": "CVE-2021-33503 (Catastrophic backtracking in URL authority parser)",
    },
    "lodash": {
        "4.17.15": "CVE-2020-8203 (Prototype pollution in zipObjectDeep)",
    },
}


class DependencyScanner(BaseScanner):
    """Scans dependency manifests and lockfiles for known vulnerabilities."""

    name: str = "dependency-audit"

    def __init__(self, offline: bool = False):
        self.offline = offline
        self.pip_audit_bin = shutil.which("pip-audit") or "pip-audit"
        self.osv_scanner_bin = shutil.which("osv-scanner") or "osv-scanner"

    def scan_path(self, path: str, **kwargs: Any) -> list[Finding]:
        """Scans dependency manifests in target directory."""
        if self.offline or kwargs.get("offline", False):
            return self._scan_offline(path)

        findings: list[Finding] = []
        p = Path(path)

        # 1. Python manifests
        req_file = (
            p / "requirements.txt" if p.is_dir() else (p if p.name == "requirements.txt" else None)
        )
        if req_file and req_file.exists():
            findings.extend(self._run_pip_audit(str(req_file)))

        # 2. Node lockfiles
        lock_file = (
            p / "package-lock.json"
            if p.is_dir()
            else (p if p.name == "package-lock.json" else None)
        )
        if lock_file and lock_file.exists():
            findings.extend(self._run_osv_scanner(str(lock_file)))

        # If tools unavailable or produced nothing, run offline database check
        if not findings:
            findings.extend(self._scan_offline(path))

        return findings

    def scan_diff(self, diff_content: str, **kwargs: Any) -> list[Finding]:
        """Scans modified manifest lines in unified diff."""
        findings: list[Finding] = []
        current_file = "unknown"
        line_no = 0

        for line in diff_content.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            if line.startswith("+") and not line.startswith("+++"):
                line_no += 1
                dep_line = line[1:].strip()
                if "==" in dep_line and current_file.endswith("requirements.txt"):
                    parts = dep_line.split("==")
                    pkg = parts[0].strip().lower()
                    ver = parts[1].split(";")[0].strip()
                    if pkg in _KNOWN_VULNERABLE_PACKAGES and ver in _KNOWN_VULNERABLE_PACKAGES[pkg]:
                        advisory = _KNOWN_VULNERABLE_PACKAGES[pkg][ver]
                        findings.append(
                            normalize_scanner_finding(
                                raw_source=self.name,
                                raw_severity="HIGH",
                                title=f"Vulnerable Dependency: {pkg}=={ver}",
                                description=f"Known vulnerability {advisory}",
                                file_path=current_file,
                                line_start=line_no,
                                line_end=line_no,
                                evidence=dep_line,
                                category=FindingCategory.DEPENDENCY,
                                confidence="HIGH",
                                remediation=f"Upgrade {pkg} to a patched version.",
                                rule_id="dependency.cve",
                            )
                        )
        return findings

    def _run_pip_audit(self, manifest_path: str) -> list[Finding]:
        if not shutil.which(self.pip_audit_bin):
            return self._check_file_offline(manifest_path)

        cmd = [
            self.pip_audit_bin,
            "--requirement",
            manifest_path,
            "--output",
            "json",
            "--no-deps",
            "--progress-spinner",
            "off",
        ]
        findings: list[Finding] = []
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.stdout:
                data = json.loads(res.stdout)
                for dep in data.get("dependencies", []):
                    pkg_name = dep.get("name")
                    version = dep.get("version")
                    for vuln in dep.get("vulns", []):
                        vid = vuln.get("id", "CVE-UNKNOWN")
                        desc = vuln.get("description", "Vulnerable dependency package")
                        fix = vuln.get("fix_versions", ["latest"])
                        findings.append(
                            normalize_scanner_finding(
                                raw_source=self.name,
                                raw_severity="HIGH",
                                title=f"Vulnerability in {pkg_name}=={version} ({vid})",
                                description=desc,
                                file_path=manifest_path,
                                line_start=1,
                                line_end=1,
                                evidence=f"Package: {pkg_name}=={version}",
                                category=FindingCategory.DEPENDENCY,
                                confidence="HIGH",
                                remediation=f"Upgrade {pkg_name} to version {', '.join(fix)}",
                                rule_id=vid,
                            )
                        )
        except Exception:
            return self._check_file_offline(manifest_path)
        return findings

    def _run_osv_scanner(self, lockfile_path: str) -> list[Finding]:
        if not shutil.which(self.osv_scanner_bin):
            return []

        cmd = [self.osv_scanner_bin, "--lockfile", lockfile_path, "--format", "json"]
        findings: list[Finding] = []
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.stdout:
                data = json.loads(res.stdout)
                for result in data.get("results", []):
                    for package in result.get("packages", []):
                        pkg = package.get("package", {})
                        pname = pkg.get("name")
                        pver = pkg.get("version")
                        for vuln in package.get("vulnerabilities", []):
                            vid = vuln.get("id", "VULN")
                            details = vuln.get("details", "Vulnerability detected by OSV")
                            findings.append(
                                normalize_scanner_finding(
                                    raw_source=self.name,
                                    raw_severity="HIGH",
                                    title=f"Vulnerability in {pname}=={pver} ({vid})",
                                    description=details,
                                    file_path=lockfile_path,
                                    line_start=1,
                                    line_end=1,
                                    evidence=f"Dependency: {pname}@{pver}",
                                    category=FindingCategory.DEPENDENCY,
                                    confidence="HIGH",
                                    remediation=f"Upgrade {pname} to a secure version.",
                                    rule_id=vid,
                                )
                            )
        except Exception:
            pass
        return findings

    def _scan_offline(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        p = Path(path)
        if p.is_file():
            files = [p]
        else:
            files = [
                f
                for f in (list(p.rglob("requirements.txt")) + list(p.rglob("package-lock.json")))
                if not is_ignored_path(f)
            ]

        for f in files:
            findings.extend(self._check_file_offline(str(f)))
        return findings

    def _check_file_offline(self, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        p = Path(file_path)
        if not p.exists():
            return findings

        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, start=1):
                clean = line.strip()
                if "==" in clean:
                    parts = clean.split("==")
                    pkg = parts[0].strip().lower()
                    ver = parts[1].split(";")[0].strip()
                    if pkg in _KNOWN_VULNERABLE_PACKAGES and ver in _KNOWN_VULNERABLE_PACKAGES[pkg]:
                        advisory = _KNOWN_VULNERABLE_PACKAGES[pkg][ver]
                        findings.append(
                            normalize_scanner_finding(
                                raw_source=self.name,
                                raw_severity="HIGH",
                                title=f"Known Vulnerable Dependency: {pkg}=={ver}",
                                description=f"Identified known vulnerability: {advisory}",
                                file_path=str(p),
                                line_start=idx,
                                line_end=idx,
                                evidence=clean,
                                category=FindingCategory.DEPENDENCY,
                                confidence="HIGH",
                                remediation=f"Upgrade {pkg} to a patched version.",
                                rule_id="dependency.cve",
                            )
                        )
        except Exception:
            pass
        return findings
