FROM public.ecr.aws/lambda/python:3.12

# Install system dependencies (git, tar, gzip; curl is pre-installed via curl-minimal)
RUN dnf install -y git tar gzip && dnf clean all

# Download and install pinned Gitleaks binary (v8.21.2)
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# Download and install pinned osv-scanner binary (v1.9.1)
RUN curl -sSL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/download/v1.9.1/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

# Copy project files
WORKDIR ${LAMBDA_TASK_ROOT}
COPY pyproject.toml README.md .gitleaks.toml ./
COPY src/ ./src/
COPY infrastructure/semgrep-rules/ ./infrastructure/semgrep-rules/

# Install python dependencies and sentinelpr package
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e . \
    && pip install --no-cache-dir semgrep==1.90.0

# Set worker handler entrypoint
CMD [ "sentinelpr.handlers.worker.handler" ]
