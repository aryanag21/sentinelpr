"""Pytest configuration and global fixtures for SentinelPR."""

import pytest


@pytest.fixture(autouse=True)
def aws_credentials_env(monkeypatch):
    """Mocks standard AWS environment variables for boto3 and moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing-key-id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing-secret-access-key")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing-security-token")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing-session-token")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
