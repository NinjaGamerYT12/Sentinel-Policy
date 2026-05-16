# Production-Hardened Dockerfile for Sentinel-Policy
# Targeted for Ubuntu 24.04 LTS on Intel x86_64

FROM ubuntu:24.04

# Metadata
LABEL maintainer="Sentinel-Policy Security Team"
LABEL description="Ultra-lightweight AI Guardrail and Auditor for MCP"

# Install Python 3.12 and cleanup to minimize image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-minimal \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Security: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a non-privileged user
RUN groupadd -r sentinel && useradd -r -g sentinel -s /sbin/nologin sentinel

# Set working directory
WORKDIR /opt/sentinel

# Security: Minimize attack surface
COPY --chown=sentinel:sentinel sentinel_policy.py constitution.json ./

# Security: Set restrictive file permissions
RUN chmod 444 constitution.json && \
    chmod 555 sentinel_policy.py && \
    touch audit.log && \
    chown sentinel:sentinel audit.log && \
    chmod 644 audit.log

# Switch to non-privileged user
USER sentinel

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 sentinel_policy.py || exit 1

# Default execution: Run self-tests on startup
ENTRYPOINT ["python3", "sentinel_policy.py"]
