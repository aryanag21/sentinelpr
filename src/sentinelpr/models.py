"""Data models and finding schemas for SentinelPR."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, value: str) -> Severity:
        norm = (value or "").strip().upper()
        if norm in ("CRITICAL", "BLOCKER"):
            return cls.CRITICAL
        if norm in ("HIGH", "ERROR"):
            return cls.HIGH
        if norm in ("MEDIUM", "MODERATE", "WARN", "WARNING"):
            return cls.MEDIUM
        if norm in ("LOW", "MINOR"):
            return cls.LOW
        return cls.INFO


class FindingCategory(StrEnum):
    SECRETS = "secrets"
    INJECTION = "injection"
    CRYPTO = "crypto"
    AUTH = "auth"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    OTHER = "other"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


class CheckConclusion(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"
    ACTION_REQUIRED = "action_required"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class Finding:
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    remediation: str = ""
    source: str = "deterministic"  # e.g., "gitleaks", "semgrep", "pip-audit", "ai"
    rule_id: str | None = None
    is_secret: bool = False
    fingerprint: str = ""
    raw_details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Computes a stable SHA-256 fingerprint for deduplication without storing raw secrets."""
        # Use a hash of evidence so plaintext secrets never form part of the raw key string
        ev_hash = hashlib.sha256(self.evidence.strip().encode("utf-8")).hexdigest()
        key = f"{self.source}:{self.rule_id or ''}:{self.file_path}:{self.line_start}:{ev_hash}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        cat = (
            FindingCategory(data["category"])
            if isinstance(data["category"], str)
            else data["category"]
        )
        sev = Severity(data["severity"]) if isinstance(data["severity"], str) else data["severity"]
        return cls(
            category=cat,
            severity=sev,
            title=data["title"],
            description=data["description"],
            file_path=data["file_path"],
            line_start=int(data["line_start"]),
            line_end=int(data.get("line_end", data["line_start"])),
            evidence=data.get("evidence", ""),
            confidence=data.get("confidence", "HIGH"),
            remediation=data.get("remediation", ""),
            source=data.get("source", "deterministic"),
            rule_id=data.get("rule_id"),
            is_secret=bool(data.get("is_secret", False)),
            fingerprint=data.get("fingerprint", ""),
            raw_details=data.get("raw_details", {}),
        )


@dataclass
class ScanResult:
    scan_id: str
    repo_id: str
    status: ScanStatus = ScanStatus.IN_PROGRESS
    pr_number: int | None = None
    commit_sha: str | None = None
    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scanners_failed: list[str] = field(default_factory=list)
    scanners_skipped: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    conclusion: CheckConclusion = CheckConclusion.NEUTRAL
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "repo_id": self.repo_id,
            "status": self.status.value,
            "pr_number": self.pr_number,
            "commit_sha": self.commit_sha,
            "findings": [f.to_dict() for f in self.findings],
            "scanners_run": self.scanners_run,
            "scanners_failed": self.scanners_failed,
            "scanners_skipped": self.scanners_skipped,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "conclusion": self.conclusion.value,
            "summary": self.summary,
        }
