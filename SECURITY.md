# Security Policy

## Reporting Security Vulnerabilities

We take the security of SentinelPR and the repositories it protects very seriously. If you discover a security vulnerability or suspect an exposure, please report it promptly.

### How to Report

- **Email**: Send vulnerability reports directly to `security@sentinelpr.local` (or file a private security advisory on GitHub).
- **Do NOT** open a public issue for sensitive vulnerabilities or credential exposures.
- Provide clear steps to reproduce, including sample payloads or commands, without attaching real credentials or production secrets.

---

## Accidental Credential Exposure & Rotation Protocol

> [!CAUTION]
> **Removing a secret in a subsequent Git commit DOES NOT protect you.**
> Once a commit containing a secret is pushed or shared, the secret is permanently stored in the repository's Git history and may have been scraped or cached.

If an API key, private key, token, or password has been accidentally committed:

1. **REVOKE & ROTATE IMMEDIATELY**:
   - Access the provider's portal (e.g. AWS IAM, GitHub, Stripe, Slack, Database).
   - Invalidate or delete the compromised credential immediately.
   - Generate a replacement credential with appropriate least-privilege scoping.
   - Deploy the new credential securely using environment variables or AWS Secrets Manager.

2. **PURGE GIT HISTORY**:
   - If the branch or commit has not yet been pushed to remote:
     ```bash
     git reset --soft HEAD~1
     # Remove secret from working tree, then commit cleanly
     ```
   - If already pushed to remote:
     - Use `git-filter-repo` or BFG Repo-Cleaner to rewrite history.
     - Note that anyone who pulled the branch may retain the secret. Rotation remains the ONLY definitive fix.

3. **AUDIT LOGS FOR UNAUTHORIZED ACCESS**:
   - Inspect cloud audit logs (AWS CloudTrail, GitHub Audit Log, database query logs) for unusual activity originating from the compromised credential during the exposure window.

---

## Defense in Depth

SentinelPR operates across three distinct security layers:

1. **Pre-Commit Hook**: Local Gitleaks check runs against staged diffs before commit creation.
2. **GitHub Actions CI**: Automated scan on pull requests blocks merging if high-confidence secrets or critical vulnerabilities exist.
3. **Serverless Webhook Auditor**: Independent serverless scanner audits pull requests asynchronously and posts inline reviews and Check Runs.
