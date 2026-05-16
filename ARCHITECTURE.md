# Sentinel-Policy: System Architecture & Security Specification

## 1. Overview
Sentinel-Policy is an ultra-lightweight, zero-dependency "Seatbelt" system designed to intercept and audit AI agent execution intents within the Model Context Protocol (MCP) framework. It operates as an inline guardrail, enforcing a "Constitution" of rules before any command or file operation is executed on the host operating system.

## 2. Core Components

### 2.1 Policy Configuration Engine
- **Mechanism**: Loads a local `constitution.json` file.
- **Integrity**: Validates the SHA-256 hash of the policy file against a hardcoded constant in the source code on every startup.
- **Matching**: Enforces strict `allow` and `deny` rules using optimized regular expressions.
- **Default Posture**: Implements a "Fail-Safe Default-Deny" logic where any non-explicitly allowed intent is blocked.

### 2.2 Cryptographic Sanitization Layer
- **Function**: Scans all execution payloads for sensitive data (PII, API keys, credentials) before logging or evaluation.
- **Patterns**: Leverages a high-performance regex suite optimized for legacy Intel x86_64 CPUs to ensure minimal latency.
- **Redaction**: Replaces sensitive data with audit-friendly placeholders (e.g., `[REDACTED_AWS_KEY]`).

### 2.3 Structural Command Parser
- **Dangerous Operation Detection**: Identifies destructive shell patterns (`rm -rf`, `dd`, etc.).
- **Path Isolation**: Prevents directory traversal (`../`) and unauthorized access to restricted system paths ( `/etc`, `/root`, `/var`, `/usr/lib/python3.12`, and the installation directory).
- **Egress Control**: Blocks unauthorized network tools (`curl`, `wget`, `nc`) to prevent data exfiltration.

### 2.4 Audit & Fail-Safe Auditor
- **Logging**: Writes every evaluation event to an append-only `audit.log` file with microsecond-precision timestamps.
- **Timeout Enforcement**: Guarantees a maximum evaluation latency of <100ms (configured to <50ms target). Any request exceeding the timeout is automatically blocked.

## 3. Security Hardening

- **Zero Dependencies**: Uses only the Python 3.11+ Standard Library to eliminate supply-chain attack vectors.
- **Non-Privileged Execution**: Designed to run as a dedicated `sentinel` user with minimal permissions.
- **Immutable Policy**: Once initialized, the policy is immutable and cannot be modified at runtime.
- **Self-Test Routine**: Includes a built-in test suite that must pass for the system to start, ensuring 100% compliance with security specifications.

## 4. Performance Metrics
- **Target Architecture**: Intel Core i5-8400 (2018-era) or newer.
- **Evaluation Latency**: <0.2ms (Average) - significantly exceeding the <50ms requirement.
- **Memory Footprint**: <20MB RSS.

## 5. Deployment
The system is delivered as a single Python script (`sentinel_policy.py`) and a configuration file (`constitution.json`), with a production-hardened `Dockerfile` for containerized environments.
