"""Unit tests for Pydantic AI schema validation."""

import pytest
from pydantic import ValidationError

from sentinelpr.ai.schemas import AIFinding, AIResponse


def test_valid_ai_schema():
    data = {
        "findings": [
            {
                "category": "injection",
                "severity": "CRITICAL",
                "title": "Command Injection",
                "description": "User input passed to shell",
                "file_path": "cmd.py",
                "line_start": 5,
                "line_end": 5,
                "evidence": "os.system(user_input)",
                "confidence": "HIGH",
                "remediation": "Avoid os.system",
                "source": "ai",
            }
        ],
        "summary": "Detected 1 critical flaw",
    }
    resp = AIResponse.model_validate(data)
    assert len(resp.findings) == 1
    assert resp.findings[0].category == "injection"


def test_invalid_category_raises():
    data = {
        "category": "not_a_real_category",
        "severity": "HIGH",
        "title": "Title",
        "description": "Desc",
        "file_path": "a.py",
        "line_start": 1,
        "line_end": 1,
        "evidence": "code",
        "confidence": "HIGH",
        "remediation": "fix",
    }
    with pytest.raises(ValidationError):
        AIFinding.model_validate(data)


def test_invalid_line_number_raises():
    data = {
        "category": "injection",
        "severity": "HIGH",
        "title": "Title",
        "description": "Desc",
        "file_path": "a.py",
        "line_start": -5,
        "line_end": 1,
        "evidence": "code",
        "confidence": "HIGH",
        "remediation": "fix",
    }
    with pytest.raises(ValidationError):
        AIFinding.model_validate(data)
