"""Unit tests for the worker Lambda handler."""

import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from moto import mock_aws

from sentinelpr.config import Settings
from sentinelpr.handlers import worker


@pytest.fixture
def mock_worker_env(monkeypatch):
    with mock_aws():
        test_settings = Settings(
            ENVIRONMENT="test",
            DYNAMODB_TABLE_NAME="sentinelpr-worker-test",
            GITHUB_APP_ID=12345,
            GITHUB_APP_PRIVATE_KEY_PEM="""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y7...
-----END RSA PRIVATE KEY-----""",
        )
        monkeypatch.setattr(worker, "get_settings", lambda: test_settings)
        monkeypatch.setattr(worker, "get_private_key_pem", lambda s: "dummy_pem")
        yield test_settings


@respx.mock
def test_worker_handler_processes_sqs_message(mock_worker_env, monkeypatch):
    # Mock GitHub Auth
    monkeypatch.setattr(
        worker.GitHubAppAuth, "get_installation_token", lambda self, iid: "mock_inst_token"
    )

    # Mock GitHub API endpoints
    respx.post("https://api.github.com/repos/org/repo/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 777})
    )
    respx.get("https://api.github.com/repos/org/repo/pulls/42").mock(
        return_value=httpx.Response(
            200, text="diff --git a/clean.py b/clean.py\n+def add(a, b): return a + b\n"
        )
    )
    respx.patch("https://api.github.com/repos/org/repo/check-runs/777").mock(
        return_value=httpx.Response(200, json={"id": 777, "status": "completed"})
    )
    respx.post("https://api.github.com/repos/org/repo/pulls/42/reviews").mock(
        return_value=httpx.Response(200, json={"id": 888})
    )

    # Mock DynamoDB
    mock_store = MagicMock()
    monkeypatch.setattr(worker, "DynamoDBStore", lambda table_name: mock_store)

    event = {
        "Records": [
            {
                "messageId": "msg-001",
                "body": json.dumps(
                    {
                        "repository": {"id": 123, "name": "repo", "owner": "org"},
                        "pull_request": {
                            "number": 42,
                            "head_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                        },
                        "installation": {"id": 555},
                    }
                ),
            }
        ]
    }

    res = worker.handler(event, None)
    assert res == {"batchItemFailures": []}
    assert mock_store.save_scan_job.called
