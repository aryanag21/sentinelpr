"""End-to-end integration test of SentinelPR local scan against synthetic fixtures."""

from pathlib import Path

from sentinelpr.models import CheckConclusion, FindingCategory
from sentinelpr.orchestration import ScanOrchestrator


def test_e2e_local_scan_against_vulnerable_fixture():
    fixture_dir = str(Path(__file__).parent.parent / "fixtures" / "vulnerable_repo")

    orchestrator = ScanOrchestrator(
        enable_ai=False,  # No Bedrock in local offline test
        offline=True,
    )

    result = orchestrator.scan_path(fixture_dir)

    # Policy outcome must be failure due to synthetic secrets and high-severity issues
    assert result.conclusion == CheckConclusion.FAILURE

    # 1. Verify Secret Detection & Masking
    secret_findings = [f for f in result.findings if f.category == FindingCategory.SECRETS]
    assert len(secret_findings) >= 1
    for sf in secret_findings:
        assert sf.is_secret is True
        # Plaintext secret MUST NOT appear
        assert "sk_test_FAKEKEYFORTESTINGONLY1234567890abcdef" not in sf.evidence
        assert "FAKE_PASSWORD_FOR_TESTING" not in sf.evidence
        assert "[REDACTED_SECRET_" in sf.evidence

    # 2. Verify SQL Injection Detection
    sqli_findings = [
        f
        for f in result.findings
        if f.category == FindingCategory.INJECTION and "sql" in f.title.lower()
    ]
    assert len(sqli_findings) >= 1
    assert "sqli.py" in sqli_findings[0].file_path

    # 3. Verify Subprocess shell=True Detection
    cmd_findings = [
        f for f in result.findings if "shell=True" in f.title or "subprocess" in f.title.lower()
    ]
    assert len(cmd_findings) >= 1
    assert "subprocess_unsafe.py" in cmd_findings[0].file_path

    # 4. Verify Vulnerable Dependency Detection
    dep_findings = [f for f in result.findings if f.category == FindingCategory.DEPENDENCY]
    assert len(dep_findings) >= 1
    assert any("requests==2.25.0" in df.title for df in dep_findings)

    # 5. Verify Clean File generates no findings
    clean_findings = [f for f in result.findings if "clean.py" in f.file_path]
    assert len(clean_findings) == 0


def test_e2e_local_scan_against_clean_file():
    clean_file = str(Path(__file__).parent.parent / "fixtures" / "vulnerable_repo" / "clean.py")

    orchestrator = ScanOrchestrator(
        enable_ai=False,
        offline=True,
    )

    result = orchestrator.scan_path(clean_file)

    assert result.conclusion == CheckConclusion.SUCCESS
    assert len(result.findings) == 0
    assert "**Total findings:** 0" in result.summary
