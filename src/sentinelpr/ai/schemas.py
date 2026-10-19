"""Pydantic schema for validating structured Bedrock AI security reviews."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AIFinding(BaseModel):
    category: Literal[
        "injection",
        "crypto",
        "auth",
        "ssrf",
        "path_traversal",
        "deserialization",
        "secrets",
        "config",
        "dependency",
        "other",
    ]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str = Field(..., max_length=200)
    description: str = Field(..., max_length=2000)
    file_path: str
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    evidence: str = Field(..., max_length=500)
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    remediation: str = Field(..., max_length=1000)
    source: Literal["ai"] = "ai"
    rule_id: str | None = None


class AIResponse(BaseModel):
    findings: list[AIFinding] = Field(default_factory=list)
    summary: str = Field(..., max_length=1000)
