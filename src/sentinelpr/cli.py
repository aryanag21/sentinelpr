"""Command-line interface for local SentinelPR scanning."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import click

from sentinelpr.models import CheckConclusion, Finding, ScanResult, Severity
from sentinelpr.orchestration import ScanOrchestrator
from sentinelpr.security.redaction import redact_text


@click.group()
@click.version_option()
def main() -> None:
    """SentinelPR: Automated Git Code Review & Security Auditor."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


@main.command(name="scan")
@click.argument("target", required=False, default=".")
@click.option("--staged", is_flag=True, help="Scan git staged changes (pre-commit use).")
@click.option(
    "--diff", "diff_range", type=str, help="Scan a git diff or commit range (e.g. HEAD~1..HEAD)."
)
@click.option("--full-history", is_flag=True, help="Audit complete git commit history.")
@click.option(
    "--offline",
    is_flag=True,
    default=True,
    help="Run in offline mode (skips remote network calls).",
)
@click.option(
    "--no-bedrock", is_flag=True, default=True, help="Disable Bedrock AI contextual analysis."
)
@click.option(
    "--severity",
    "min_severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="LOW",
    help="Minimum severity level to display.",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output report format.",
)
def scan_command(
    target: str,
    staged: bool,
    diff_range: str | None,
    full_history: bool,
    offline: bool,
    no_bedrock: bool,
    min_severity: str,
    output_format: str,
) -> None:
    """Scans files, directories, or Git diffs for secrets and security issues."""
    orchestrator = ScanOrchestrator(
        enable_ai=not no_bedrock,
        offline=offline,
    )

    result: ScanResult

    if staged:
        click.echo("[*] Inspecting git staged changes...")
        diff_text = _get_git_diff(["--staged"])
        if not diff_text.strip():
            click.echo("No staged changes detected.")
            sys.exit(0)
        result = orchestrator.scan_diff(diff_text)

    elif diff_range:
        click.echo(f"[*] Inspecting git diff range: {diff_range}...")
        diff_text = _get_git_diff([diff_range])
        if not diff_text.strip():
            click.echo(f"No diff found for range {diff_range}.")
            sys.exit(0)
        result = orchestrator.scan_diff(diff_text)

    else:
        target_path = os.path.abspath(target)
        click.echo(f"[*] Scanning path: {target_path}...")
        result = orchestrator.scan_path(target_path)

    # Filter findings by minimum severity
    min_sev_enum = Severity.from_str(min_severity)
    sev_ranks = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    filtered_findings = [
        f for f in result.findings if sev_ranks[f.severity] >= sev_ranks[min_sev_enum]
    ]

    # Render output format
    if output_format.lower() == "json":
        data = result.to_dict()
        data["findings"] = [f.to_dict() for f in filtered_findings]
        click.echo(json.dumps(data, indent=2))

    elif output_format.lower() == "sarif":
        sarif = _generate_sarif(result, filtered_findings)
        click.echo(json.dumps(sarif, indent=2))

    else:
        _render_text_report(result, filtered_findings)

    # Determine exit code based on policy conclusion
    if result.conclusion == CheckConclusion.FAILURE:
        sys.exit(1)
    sys.exit(0)


def _get_git_diff(args: list[str]) -> str:
    """Executes git diff safely."""
    try:
        cmd = ["git", "diff"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.stdout
    except Exception as e:
        click.echo(f"Error executing git diff: {e}", err=True)
        return ""


def _render_text_report(result: ScanResult, findings: list[Finding]) -> None:
    click.echo("\n" + "=" * 70)
    click.echo(f"  SentinelPR Security Scan Summary: [{result.conclusion.value.upper()}]")
    click.echo("=" * 70)
    click.echo(f"* Total Findings: {len(findings)}")
    click.echo(f"* Scanners executed: {', '.join(result.scanners_run) or 'None'}")
    if result.scanners_failed:
        click.echo(f"* [!] Degraded Scanners: {', '.join(result.scanners_failed)}")
    click.echo("-" * 70)

    if not findings:
        click.secho("[+] No security vulnerabilities detected.", fg="green", bold=True)
        return

    for f in findings:
        color = (
            "red"
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
            else ("yellow" if f.severity == Severity.MEDIUM else "cyan")
        )
        click.secho(f"\n[{f.severity.value}] {f.title}", fg=color, bold=True)
        click.echo(f"  File: {f.file_path}:{f.line_start}")
        click.echo(
            f"  Category: {f.category.value} | Source: {f.source} | Fingerprint: {f.fingerprint}"
        )
        if f.evidence:
            # Strictly ensure evidence has been redacted before writing to console
            safe_evidence = redact_text(f.evidence)
            click.echo(f"  Evidence: {safe_evidence}")
        if f.remediation:
            click.echo(f"  Remediation: {f.remediation}")


def _generate_sarif(result: ScanResult, findings: list[Finding]) -> dict[str, Any]:
    """Generates standard SARIF 2.1.0 output for GitHub Code Scanning integration."""
    rules = []
    results = []
    rule_ids: set[str] = set()

    for f in findings:
        rid = f.rule_id or f"sentinelpr.{f.category.value}"
        if rid not in rule_ids:
            rule_ids.add(rid)
            rules.append(
                {
                    "id": rid,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": "error"
                        if f.severity in (Severity.CRITICAL, Severity.HIGH)
                        else "warning"
                    },
                }
            )

        results.append(
            {
                "ruleId": rid,
                "message": {"text": f"{f.description} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": f.line_start,
                                "endLine": max(f.line_end, f.line_start),
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentinelPR",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


if __name__ == "__main__":
    main()
