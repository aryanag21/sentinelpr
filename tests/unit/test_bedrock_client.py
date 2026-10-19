"""Unit tests for Bedrock Runtime client."""

import io
import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from sentinelpr.ai.bedrock_client import (
    BedrockClient,
    BedrockThrottlingError,
    BedrockUnavailableError,
)


def test_bedrock_client_successful_invoke():
    mock_boto_client = MagicMock()
    mock_response_body = {
        "content": [{"type": "text", "text": '{"findings":[],"summary":"Clean"}'}],
    }
    mock_boto_client.invoke_model.return_value = {
        "body": io.BytesIO(json.dumps(mock_response_body).encode("utf-8")),
    }

    client = BedrockClient(client=mock_boto_client)
    res = client.invoke("Test prompt")

    assert '{"findings":[],"summary":"Clean"}' in res
    assert mock_boto_client.invoke_model.called


def test_bedrock_client_throttling_retries_and_raises():
    mock_boto_client = MagicMock()
    error_response = {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}
    mock_boto_client.invoke_model.side_effect = ClientError(error_response, "InvokeModel")

    client = BedrockClient(client=mock_boto_client, max_retries=2)
    with pytest.raises(BedrockThrottlingError):
        client.invoke("Test prompt")

    assert mock_boto_client.invoke_model.call_count == 2


def test_bedrock_client_unavailable_raises():
    mock_boto_client = MagicMock()
    error_response = {"Error": {"Code": "ServiceUnavailable", "Message": "Service down"}}
    mock_boto_client.invoke_model.side_effect = ClientError(error_response, "InvokeModel")

    client = BedrockClient(client=mock_boto_client, max_retries=1)
    with pytest.raises(BedrockUnavailableError):
        client.invoke("Test prompt")
