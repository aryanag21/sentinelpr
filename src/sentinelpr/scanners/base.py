"""Base interface for SentinelPR security scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from sentinelpr.models import Finding

IGNORED_DIRS = {
    ".venv",
    "venv",
    "env",
    ".git",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
}


def is_ignored_path(path: Path) -> bool:
    """Checks if a file path belongs to virtualenvs, vendor dirs, caches, or VCS."""
    for part in path.parts:
        if part in IGNORED_DIRS or part.startswith((".venv", ".git", ".pytest", ".ruff")):
            return True
    return False


class BaseScanner(ABC):
    """Abstract base class that all security scanners must implement."""

    name: str = "base"

    @abstractmethod
    def scan_path(self, path: str, **kwargs: Any) -> list[Finding]:
        """Scans a directory path or file."""
        raise NotImplementedError

    @abstractmethod
    def scan_diff(self, diff_content: str, **kwargs: Any) -> list[Finding]:
        """Scans a git diff patch string."""
        raise NotImplementedError
