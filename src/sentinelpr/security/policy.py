"""Policy evaluation, finding normalization, deduplication, and Check Run conclusion calculation."""

from __future__ import annotations

from collections.abc import Iterable

from sentinelpr.models import (
    CheckConclusion,
    Finding,
    FindingCategory,
    Severity,
)


def normalize_scanner_finding(
    raw_source: str,
    raw_severity: str,
    title: str,
    description: str,
    file_path: str,
    line_start: int,
    line_end: int,
    evidence: str,
    category: FindingCategory = FindingCategory.OTHER,
    confidence: str = "HIGH",
    remediation: str = "",
    rule_id: str | None = None,
    is_secret: bool = False,
    raw_details: dict | None = None,
) -> Finding:
    """Normalizes a raw scanner output into a standardized SentinelPR Finding."""
    raw_sev = (raw_severity or "").strip().upper()
    source_lower = raw_source.lower()

    # Default mapping
    severity = Severity.from_str(raw_sev)

    if "gitleaks" in source_lower or is_secret:
        is_secret = True
        category = FindingCategory.SECRETS
        if raw_sev in ("HIGH", "CRITICAL"):
            severity = Severity.CRITICAL
        elif raw_sev in ("MEDIUM", "MODERATE"):
            severity = Severity.HIGH
        else:
            severity = Severity.HIGH
        if not remediation:
            remediation = "Revoke and rotate this credential immediately. Removing it from the file does not purge Git history."

    elif "semgrep" in source_lower:
        if raw_sev == "ERROR":
            severity = Severity.HIGH
        elif raw_sev == "WARNING":
            severity = Severity.MEDIUM
        elif raw_sev == "INFO":
            severity = Severity.LOW

    elif "audit" in source_lower or "osv" in source_lower:
        category = FindingCategory.DEPENDENCY
        if raw_sev in ("CRITICAL",):
            severity = Severity.CRITICAL
        elif raw_sev in ("HIGH",):
            severity = Severity.HIGH
        elif raw_sev in ("MODERATE", "MEDIUM"):
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

    elif "ai" in source_lower or "bedrock" in source_lower:
        if confidence.upper() == "LOW":
            severity = Severity.INFO

    return Finding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        evidence=evidence,
        confidence=confidence.upper(),
        remediation=remediation,
        source=raw_source,
        rule_id=rule_id,
        is_secret=is_secret,
        raw_details=raw_details or {},
    )


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicates findings by their stable SHA-256 fingerprint, preserving original order."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)
    return unique


def evaluate_policy(
    findings: list[Finding],
    scanners_failed: list[str] | None = None,
    scanners_skipped: list[str] | None = None,
    warn_only_mode: bool = False,
    fail_on_high_secrets: bool = True,
) -> tuple[CheckConclusion, str]:
    """Evaluates scan findings against security policy and produces a GitHub Check Run conclusion and summary.

    Policy Rules:
    1. Any confirmed secret -> failure (unless warn_only_mode)
    2. Deterministic CRITICAL or HIGH -> failure (unless warn_only_mode)
    3. Deterministic MEDIUM -> neutral (warning)
    4. AI-only CRITICAL/HIGH -> neutral (AI findings alone never block PR by default)
    5. LOW/INFO only -> success
    6. No findings -> success
    """
    scanners_failed = scanners_failed or []
    scanners_skipped = scanners_skipped or []

    # Count breakdown
    det_findings = [f for f in findings if f.source not in ("ai", "bedrock")]
    ai_findings = [f for f in findings if f.source in ("ai", "bedrock")]

    secret_findings = [f for f in findings if f.is_secret]
    det_blockers = [f for f in det_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    det_warnings = [f for f in det_findings if f.severity == Severity.MEDIUM]
    ai_highs = [f for f in ai_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    has_fatal_secret = bool(secret_findings) if fail_on_high_secrets else False
    has_blockers = bool(det_blockers) or has_fatal_secret

    if has_blockers:
        conclusion = CheckConclusion.FAILURE
    elif det_warnings or ai_highs:
        conclusion = CheckConclusion.NEUTRAL
    else:
        conclusion = CheckConclusion.SUCCESS

    if warn_only_mode and conclusion == CheckConclusion.FAILURE:
        conclusion = CheckConclusion.NEUTRAL

    # Build human-readable summary
    summary_lines: list[str] = [
        f"### SentinelPR Security Audit: {conclusion.value.upper()}",
        "",
        f"- **Total findings:** {len(findings)} ({len(det_findings)} deterministic, {len(ai_findings)} AI contextual)",
        f"- **Secrets detected:** {len(secret_findings)}",
        f"- **Critical / High deterministic issues:** {len(det_blockers)}",
        f"- **Medium / Warning issues:** {len(det_warnings)}",
        f"- **Low / Informational:** {len([f for f in findings if f.severity in (Severity.LOW, Severity.INFO)])}",
    ]

    if scanners_failed:
        summary_lines.append(
            f"- ⚠️ **Degraded mode:** Scanners failed: {', '.join(scanners_failed)}"
        )
    if scanners_skipped:
        summary_lines.append(f"- ℹ️ Scanners skipped: {', '.join(scanners_skipped)}")

    if secret_findings:
        summary_lines.extend(
            [
                "",
                "#### 🚨 Critical Action Required: Exposed Secrets",
                "One or more credentials were detected. **Revoke and rotate them immediately.**",
                "Note: Purging the secret from the file in a subsequent commit does NOT remove it from Git history.",
            ]
        )

    if det_blockers:
        summary_lines.extend(
            [
                "",
                "#### 🛑 High-Priority Vulnerabilities",
            ]
        )
        for b in det_blockers[:5]:
            summary_lines.append(
                f"- **[{b.severity.value}]** `{b.file_path}:{b.line_start}` - {b.title}"
            )

    return conclusion, "\n".join(summary_lines)
