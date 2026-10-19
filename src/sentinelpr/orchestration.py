"""Central security scan orchestrator coordinating scanners, AI, and policy."""

from __future__ import annotations

import logging
import uuid

from sentinelpr.ai.analysis import run_ai_security_review
from sentinelpr.ai.bedrock_client import BedrockClient
from sentinelpr.models import Finding, ScanResult, ScanStatus
from sentinelpr.scanners.base import BaseScanner
from sentinelpr.scanners.configuration import ConfigurationScanner
from sentinelpr.scanners.dependencies import DependencyScanner
from sentinelpr.scanners.secrets import SecretScanner
from sentinelpr.scanners.semgrep_scanner import SemgrepScanner
from sentinelpr.security.policy import deduplicate_findings, evaluate_policy

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates deterministic scanners, AI review, and policy evaluation."""

    def __init__(
        self,
        enable_ai: bool = True,
        offline: bool = False,
        bedrock_client: BedrockClient | None = None,
        custom_scanners: list[BaseScanner] | None = None,
        warn_only_mode: bool = False,
        fail_on_high_secrets: bool = True,
    ):
        self.enable_ai = enable_ai
        self.offline = offline
        self.bedrock_client = bedrock_client
        self.warn_only_mode = warn_only_mode
        self.fail_on_high_secrets = fail_on_high_secrets

        if custom_scanners is not None:
            self.scanners = custom_scanners
        else:
            self.scanners = [
                SecretScanner(),
                SemgrepScanner(),
                DependencyScanner(offline=offline),
                ConfigurationScanner(),
            ]

    def scan_diff(
        self,
        diff_content: str,
        repo_id: str = "local",
        pr_number: int | None = None,
        commit_sha: str | None = None,
    ) -> ScanResult:
        """Executes a complete scan against a unified diff."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(
            scan_id=scan_id,
            repo_id=repo_id,
            pr_number=pr_number,
            commit_sha=commit_sha,
            status=ScanStatus.IN_PROGRESS,
        )

        all_findings: list[Finding] = []

        # 1. Run deterministic scanners
        for scanner in self.scanners:
            scanner_name = scanner.name
            try:
                findings = scanner.scan_diff(diff_content)
                all_findings.extend(findings)
                result.scanners_run.append(scanner_name)
            except Exception as e:
                logger.error("Scanner '%s' failed during diff scan: %s", scanner_name, e)
                result.scanners_failed.append(scanner_name)

        # 2. Run Bedrock AI contextual review if enabled and not offline
        if self.enable_ai and not self.offline:
            try:
                ai_findings, ai_summary, degraded = run_ai_security_review(
                    diff_content=diff_content,
                    deterministic_findings=all_findings,
                    client=self.bedrock_client,
                )
                all_findings.extend(ai_findings)
                result.scanners_run.append("bedrock")
                if degraded:
                    result.scanners_failed.append("bedrock-degraded")
            except Exception as e:
                logger.error("AI review failed: %s", e)
                result.scanners_failed.append("bedrock")
        else:
            result.scanners_skipped.append("bedrock")

        # 3. Deduplicate findings
        unique_findings = deduplicate_findings(all_findings)
        result.findings = unique_findings

        # 4. Evaluate policy
        conclusion, summary = evaluate_policy(
            findings=unique_findings,
            scanners_failed=result.scanners_failed,
            scanners_skipped=result.scanners_skipped,
            warn_only_mode=self.warn_only_mode,
            fail_on_high_secrets=self.fail_on_high_secrets,
        )
        result.conclusion = conclusion
        result.summary = summary
        result.status = ScanStatus.PARTIAL if result.scanners_failed else ScanStatus.SUCCESS

        return result

    def scan_path(
        self,
        path: str,
        repo_id: str = "local",
    ) -> ScanResult:
        """Executes a complete scan against a local directory or file path."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(
            scan_id=scan_id,
            repo_id=repo_id,
            status=ScanStatus.IN_PROGRESS,
        )

        all_findings: list[Finding] = []

        for scanner in self.scanners:
            scanner_name = scanner.name
            try:
                findings = scanner.scan_path(path)
                all_findings.extend(findings)
                result.scanners_run.append(scanner_name)
            except Exception as e:
                logger.error("Scanner '%s' failed during path scan: %s", scanner_name, e)
                result.scanners_failed.append(scanner_name)

        # Path scanning does not invoke Bedrock by default
        result.scanners_skipped.append("bedrock")

        unique_findings = deduplicate_findings(all_findings)
        result.findings = unique_findings

        conclusion, summary = evaluate_policy(
            findings=unique_findings,
            scanners_failed=result.scanners_failed,
            scanners_skipped=result.scanners_skipped,
            warn_only_mode=self.warn_only_mode,
            fail_on_high_secrets=self.fail_on_high_secrets,
        )
        result.conclusion = conclusion
        result.summary = summary
        result.status = ScanStatus.PARTIAL if result.scanners_failed else ScanStatus.SUCCESS

        return result
