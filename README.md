# SentinelPR: Automated Git Code Review & Security Auditor

SentinelPR is a production-grade, GitHub-integrated security auditing system designed to prevent accidental exposure of secrets, scan pull requests for common vulnerabilities, conduct contextual AI-powered reviews using Amazon Bedrock, and publish actionable inline comments, summaries, and Check Runs on GitHub.

---

## Key Features

- **Deterministic Secret Detection**: Integrates Gitleaks to catch committed API keys, tokens, and credentials before they leave the developer machine.
- **Fail-Safe Secret Masking**: Secret values are **never** logged, printed in reports, or posted in GitHub comments; cryptographic SHA-256 fingerprints are used for deduplication.
- **Static Application Security Testing (SAST)**: Language-aware static analysis via Semgrep with pinned, vetted local security rule packs (Python & JS/TS).
- **Dependency Vulnerability Audits**: Integration with `pip-audit` and `osv-scanner` across Python and JavaScript manifests without executing untrusted build commands.
- **Contextual Bedrock Analysis**: Isolated Amazon Bedrock (Claude 3.5 Haiku) integration evaluating redacted code snippets with strict token bounds and prompt-injection defense.
- **Resilient Serverless Architecture**: Asynchronous webhook ingestion via AWS API Gateway, Lambda, SQS (with DLQ), and DynamoDB single-table persistence.
- **Local Developer Workflow**: Standalone CLI (`sentinelpr scan`) and pre-commit hook operating completely without AWS credentials.

---

## Architecture Overview

```
[ Developer ] --(pre-commit / CLI)--> [ Gitleaks + Semgrep Local ]
      |
      v (Git Push / PR)
[ GitHub PR Webhook ]
      |
      v (HMAC-SHA256 Signed)
[ Amazon API Gateway ]
      |
      v
[ Ingestion Lambda ] --(Validates signature, dedupes delivery ID)
      |
      v
[ Amazon SQS Queue ] --(DLQ on max retries)
      |
      v
[ Worker Lambda (Container Image) ]
   ├── GitHub API (Fetch PR diff & file tree)
   ├── Deterministic Scanners (Gitleaks, Semgrep, osv/pip-audit)
   ├── Amazon Bedrock (Contextual analysis on redacted snippets)
   ├── Policy & Normalization Engine (Deduplication & severity ranking)
   ├── DynamoDB (Store scan job, findings & fingerprints)
   └── GitHub API (Publish Check Run, inline review comments, summary)
```

---

## 1. Local Development Setup

### Prerequisites

- Python 3.12+
- Git 2.40+
- Gitleaks v8.21+ (optional for local system, packaged in container for AWS)

### Installation

```bash
# Clone the repository
cd cad_project

# Set up and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

---

## 2. Using the Local CLI

The CLI operates fully offline and requires no AWS credentials:

```bash
# Scan working directory or path
sentinelpr scan .

# Scan git staged changes (matches pre-commit hook)
sentinelpr scan --staged

# Scan a git diff or commit range
sentinelpr scan --diff HEAD~1..HEAD

# Run in offline mode (skips remote vulnerability DB checks)
sentinelpr scan --offline

# Scan synthetic test fixture
sentinelpr scan tests/fixtures/vulnerable_repo/
```

### Safe Secret Masking Demonstration

When SentinelPR detects a secret, the terminal output strictly masks the token:

```
[CRITICAL] Detected Stripe API Key (gitleaks:stripe-api-key)
  File: tests/fixtures/vulnerable_repo/secrets.py:1
  Fingerprint: 8a7c29e1f...
  Remediation: Revoke and rotate this credential immediately. Removing it from the file does not purge Git history.
```

---

## 3. GitHub App Configuration

1. Go to **GitHub Settings > Developer Settings > GitHub Apps > New GitHub App**.
2. **Webhook URL**: Enter your deployed API Gateway endpoint (e.g., `https://api.yourdomain.com/webhook`).
3. **Webhook Secret**: Generate a cryptographically random secret string and save it.
4. **Permissions**:
   - `Pull Requests`: Read & Write
   - `Checks`: Read & Write
   - `Contents`: Read
   - `Metadata`: Read
5. **Subscribe to Events**:
   - Check `Pull request`
   - Check `Check suite`
6. Generate and download a **Private Key (PEM)**.
7. Note down the **App ID**.

---

## 4. AWS Infrastructure Deployment

### Store Secrets in AWS Secrets Manager

```bash
# 1. Store GitHub App Private Key PEM
aws secretsmanager create-secret \
    --name "sentinelpr/github-app-key-dev" \
    --description "SentinelPR GitHub App Private Key" \
    --secret-string file://path/to/private-key.pem

# 2. Store GitHub Webhook Secret
aws secretsmanager create-secret \
    --name "sentinelpr/webhook-secret-dev" \
    --description "SentinelPR GitHub Webhook Secret" \
    --secret-string "YOUR_WEBHOOK_SECRET_STRING"
```

### Build & Deploy with SAM

```bash
# Validate SAM template
sam validate --template infrastructure/template.yaml

# Build container image and package
sam build --template infrastructure/template.yaml

# Deploy stack
sam deploy --guided
```

---

## 5. Teardown & Resource Cleanup

To remove all deployed AWS resources and avoid ongoing charges:

```bash
# Delete CloudFormation stack
sam delete --stack-name sentinelpr-dev

# Delete Secrets from Secrets Manager
aws secretsmanager delete-secret --secret-id "sentinelpr/github-app-key-dev" --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id "sentinelpr/webhook-secret-dev" --force-delete-without-recovery
```

---

## 6. Testing

Run the automated test suite locally:

```bash
# Run all unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run test coverage report
pytest --cov=sentinelpr tests/
```
