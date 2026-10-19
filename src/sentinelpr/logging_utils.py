"""Structured logging with automated secret redaction for SentinelPR."""

from __future__ import annotations

import logging

from aws_lambda_powertools import Logger

from sentinelpr.security.redaction import redact_dict, redact_text


class RedactingFilter(logging.Filter):
    """Logging filter that automatically redacts credentials from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        elif isinstance(record.msg, dict):
            record.msg = redact_dict(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_text(a)
                    if isinstance(a, str)
                    else (redact_dict(a) if isinstance(a, dict) else a)
                    for a in record.args
                )
        return True


def get_logger(service_name: str = "sentinelpr") -> Logger:
    """Creates a configured AWS Lambda Powertools Logger with secret redaction enabled."""
    logger = Logger(service=service_name)
    redact_filter = RedactingFilter()

    # Attach filter to powertools logger handlers and root logger
    for handler in logging.root.handlers:
        handler.addFilter(redact_filter)

    return logger
