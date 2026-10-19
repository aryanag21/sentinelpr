"""AI analysis orchestrator: prompt construction, invocation, schema validation, and normalization."""

from __future__ import annotations

import json
import logging
import re

from pydantic import ValidationError

from sentinelpr.ai.bedrock_client import BedrockClient, BedrockError
from sentinelpr.ai.prompts import build_review_prompt
from sentinelpr.ai.schemas import AIResponse
from sentinelpr.models import Finding, FindingCategory
from sentinelpr.security.policy import normalize_scanner_finding
from sentinelpr.security.redaction import redact_text

logger = logging.getLogger(__name__)


def run_ai_security_review(
    diff_content: str,
    deterministic_findings: list[Finding],
    client: BedrockClient | None = None,
) -> tuple[list[Finding], str, bool]:
    """Conducts contextual AI security review on diff and deterministic findings.

    Returns:
        tuple of (ai_findings, ai_summary, is_degraded_or_failed)
    """
    if not diff_content.strip():
        return [], "No diff changes to review.", False

    client = client or BedrockClient()

    # Redact diff content
    redacted_diff = redact_text(diff_content)

    # Summarize deterministic findings for context
    det_summary = [
        {
            "category": f.category.value,
            "severity": f.severity.value,
            "title": f.title,
            "file": f.file_path,
            "line": f.line_start,
        }
        for f in deterministic_findings
    ]
    det_json = json.dumps(det_summary, indent=2)

    prompt = build_review_prompt(
        redacted_diff=redacted_diff,
        deterministic_findings_json=det_json,
    )

    try:
        raw_response = client.invoke(prompt)
    except BedrockError as e:
        logger.warning("Bedrock invocation failed, proceeding in degraded mode: %s", e)
        return [], f"AI review unavailable (Bedrock error: {e})", True
    except Exception as e:
        logger.error("Unexpected error invoking Bedrock: %s", e)
        return [], f"AI review failed unexpectedly: {e}", True

    # Parse and validate JSON
    parsed_response, parse_err = _parse_and_validate_ai_response(raw_response)
    if parse_err or parsed_response is None:
        logger.warning("Discarded malformed AI response: %s", parse_err)
        return [], f"AI review degraded (Malformed output: {parse_err})", True

    # Normalise valid AI findings into standard Finding objects
    ai_findings: list[Finding] = []
    for item in parsed_response.findings:
        try:
            finding = normalize_scanner_finding(
                raw_source="bedrock",
                raw_severity=item.severity,
                title=item.title,
                description=item.description,
                file_path=item.file_path,
                line_start=item.line_start,
                line_end=item.line_end,
                evidence=item.evidence,
                category=FindingCategory(item.category),
                confidence=item.confidence,
                remediation=item.remediation,
                rule_id=item.rule_id or "bedrock.contextual",
                is_secret=item.category == "secrets",
            )
            ai_findings.append(finding)
        except Exception as e:
            logger.debug("Failed normalizing AI finding '%s': %s", item.title, e)

    return ai_findings, parsed_response.summary, False


def _parse_and_validate_ai_response(raw_text: str) -> tuple[AIResponse | None, str | None]:
    """Strips Markdown fences if present and validates against the Pydantic AIResponse schema."""
    if not raw_text:
        return None, "Empty response from Bedrock"

    cleaned = raw_text.strip()

    # Extract JSON if enclosed in markdown code fences ```json ... ```
    if "```" in cleaned:
        match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", cleaned)
        if match:
            cleaned = match.group(1).strip()
        else:
            # Try removing leading/trailing backticks
            cleaned = re.sub(r"^```(?:json)?|```$", "", cleaned).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON syntax: {e}"

    try:
        validated = AIResponse.model_validate(data)
        return validated, None
    except ValidationError as e:
        return None, f"Schema validation error: {e}"
