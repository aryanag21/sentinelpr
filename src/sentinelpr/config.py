"""Configuration management for SentinelPR."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General
    environment: str = Field(default="dev", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # GitHub App Configuration
    github_app_id: int | None = Field(default=None, alias="GITHUB_APP_ID")
    github_app_private_key_secret_arn: str | None = Field(
        default=None, alias="GITHUB_APP_PRIVATE_KEY_SECRET_ARN"
    )
    github_app_private_key_pem: str | None = Field(default=None, alias="GITHUB_APP_PRIVATE_KEY_PEM")
    github_webhook_secret_arn: str | None = Field(default=None, alias="GITHUB_WEBHOOK_SECRET_ARN")
    github_webhook_secret: str | None = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")
    allowed_repo_ids: str = Field(default="", alias="ALLOWED_REPO_IDS")

    # AWS Bedrock Configuration
    bedrock_model_id: str = Field(
        default="anthropic.claude-3-5-haiku-20241022-v1:0", alias="BEDROCK_MODEL_ID"
    )
    bedrock_region: str = Field(default="us-east-1", alias="BEDROCK_REGION")

    # AWS Storage & SQS
    dynamodb_table_name: str = Field(default="sentinelpr-dev", alias="DYNAMODB_TABLE_NAME")
    scan_queue_url: str | None = Field(default=None, alias="SCAN_QUEUE_URL")

    # Policy & Scanners
    max_inline_comments: int = Field(default=25, alias="MAX_INLINE_COMMENTS")
    fail_on_high_secrets: bool = Field(default=True, alias="FAIL_ON_HIGH_SECRETS")
    warn_only_mode: bool = Field(default=False, alias="WARN_ONLY_MODE")
    semgrep_rules_path: str = Field(
        default="infrastructure/semgrep-rules", alias="SEMGREP_RULES_PATH"
    )

    def is_repo_allowed(self, repo_id: int | str) -> bool:
        """Checks if a given repository ID is allowed to be scanned."""
        if not self.allowed_repo_ids.strip():
            # If empty, allow all repos in dev/testing unless explicitly locked down
            return True
        allowed = [r.strip() for r in self.allowed_repo_ids.split(",") if r.strip()]
        return str(repo_id) in allowed


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance
