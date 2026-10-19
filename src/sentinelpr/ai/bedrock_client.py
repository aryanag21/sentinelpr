"""Amazon Bedrock Runtime client with retries, timeouts, and backoff."""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from sentinelpr.ai.prompts import SYSTEM_PROMPT
from sentinelpr.security.redaction import redact_text

logger = logging.getLogger(__name__)


class BedrockError(Exception):
    """Base exception for Bedrock client failures."""


class BedrockThrottlingError(BedrockError):
    """Raised when Bedrock throttles requests."""


class BedrockUnavailableError(BedrockError):
    """Raised when Bedrock is unreachable or returns 5xx."""


class BedrockClient:
    """Manages invocations to Amazon Bedrock models."""

    def __init__(
        self,
        model_id: str = "anthropic.claude-3-5-haiku-20241022-v1:0",
        region_name: str = "us-east-1",
        timeout_seconds: int = 30,
        max_retries: int = 3,
        client: Any | None = None,
    ):
        self.model_id = model_id
        self.region_name = region_name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

        if client is not None:
            self.client = client
        else:
            config = Config(
                connect_timeout=10,
                read_timeout=timeout_seconds,
                retries={"max_attempts": 0},  # Custom backoff handled in code
            )
            self.client = boto3.client(
                "bedrock-runtime",
                region_name=self.region_name,
                config=config,
            )

    def invoke(self, prompt: str) -> str:
        """Invokes the Bedrock model with automatic exponential backoff."""
        # Redact prompt content before dispatching
        safe_prompt = redact_text(prompt)

        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "temperature": 0.0,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": safe_prompt}],
            }
        )

        delay = 1.0
        last_exception: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.invoke_model(
                    modelId=self.model_id,
                    contentType="application/json",
                    accept="application/json",
                    body=body,
                )
                response_body = json.loads(response["body"].read().decode("utf-8"))

                # Extract text content from Anthropic response structure
                content_blocks = response_body.get("content", [])
                text_parts = [
                    block.get("text", "") for block in content_blocks if block.get("type") == "text"
                ]
                return "".join(text_parts).strip()

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                last_exception = e

                if error_code in (
                    "ThrottlingException",
                    "RequestLimitExceeded",
                    "TooManyRequestsException",
                ):
                    if attempt == self.max_retries:
                        raise BedrockThrottlingError(
                            f"Bedrock throttled after {attempt} attempts: {e}"
                        ) from e
                    # Jittered exponential backoff
                    sleep_time = delay + secrets.SystemRandom().uniform(0.1, 0.5)
                    logger.warning(
                        "Bedrock throttled, retrying in %.2fs (attempt %d/%d)",
                        sleep_time,
                        attempt,
                        self.max_retries,
                    )
                    time.sleep(sleep_time)
                    delay *= 2.0
                elif error_code in ("ServiceUnavailable", "InternalServerError"):
                    if attempt == self.max_retries:
                        raise BedrockUnavailableError(
                            f"Bedrock service unavailable after {attempt} attempts: {e}"
                        ) from e
                    time.sleep(delay)
                    delay *= 2.0
                else:
                    raise BedrockError(f"Bedrock client error: {e}") from e
            except Exception as e:
                last_exception = e
                if attempt == self.max_retries:
                    raise BedrockError(f"Bedrock invocation failed: {e}") from e
                time.sleep(delay)
                delay *= 2.0

        raise BedrockError(
            f"Bedrock invocation failed after {self.max_retries} retries: {last_exception}"
        )
