# Contributing to SentinelPR

Thank you for your interest in contributing to SentinelPR! Please review this guide to set up your development environment and adhere to our security and coding standards.

---

## 1. Development Setup

### Prerequisites

- Python 3.12+
- Git 2.40+
- Gitleaks (v8.21+) installed on PATH (or via pre-commit)
- AWS SAM CLI (for validating and deploying serverless templates)

### Initializing Environment

```bash
# Clone the repository
git clone https://github.com/your-org/sentinelpr.git
cd sentinelpr

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package in editable mode with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

---

## 2. Local Secret Hygiene & Testing Policy

> [!IMPORTANT]
> **Strict No-Real-Secrets Policy:**
> - Never commit real API keys, tokens, or credentials anywhere in the repository.
> - When creating test fixtures or test cases, use synthetic, fake secrets only (e.g. prefixed with `FAKE_` or dummy formats).
> - Annotate synthetic fixture secrets with `# gitleaks:allow` to prevent pre-commit or CI false alarms.

---

## 3. Running Scans Locally

SentinelPR includes a local CLI that runs independently without requiring AWS credentials:

```bash
# Scan working tree changes
sentinelpr scan

# Scan staged changes (like pre-commit)
sentinelpr scan --staged

# Scan a specific directory or diff
sentinelpr scan tests/fixtures/vulnerable_repo/
sentinelpr scan --diff HEAD~1..HEAD

# Run in offline mode (skipping network-dependent dependency checks)
sentinelpr scan --offline
```

---

## 4. Code Standards & Testing

All contributions must pass automated linting, formatting, and unit/integration tests:

```bash
# Lint and format checks
ruff check .
ruff format --check .

# Run test suite
pytest
```

---

## 5. GitHub App Permission Manifest

When configuring the GitHub App for SentinelPR, grant strictly the minimum required permissions:

| Permission | Level | Justification |
| :--- | :--- | :--- |
| **Pull Requests** | Read & Write | Read PR changed files and post inline review comments |
| **Checks** | Read & Write | Create and update Check Runs reflecting audit results |
| **Contents** | Read | Fetch source context lines surrounding diff hunks |
| **Metadata** | Read | Mandatory base permission for GitHub Apps |

**Subscribed Webhook Events**:
- `pull_request` (events: `opened`, `reopened`, `synchronize`)
- `check_suite` (events: `rerequested`)
