#!/usr/bin/env python3
"""
Sentinel-Policy: An ultra-lightweight, zero-dependency Constitutional AI Guardrail and Auditor.
Optimized for MCP (Model Context Protocol) on legacy Intel x86_64 architectures.
"""

import json
import hashlib
import re
import os
import sys
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# --- CONFIGURATION & CONSTANTS ---
CONSTITUTION_PATH = os.path.join(os.path.dirname(__file__), "constitution.json")
# Hardcoded SHA-256 of constitution.json for tamper-proof validation
EXPECTED_CONSTITUTION_HASH = "792d5ac695f3a357065609ca0126cda728aba9e5dc6dba6608e6263e88a1a788"
LOG_FILE = os.path.join(os.path.dirname(__file__), "audit.log")
MAX_EVALUATION_TIME_MS = 100

# Setup basic logging to append-only file
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [SENTINEL-AUDIT] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)

class SentinelPolicy:
    """Core security engine for evaluating and sanitizing execution intents."""

    def __init__(self, constitution_path: str = CONSTITUTION_PATH):
        self.constitution_path = constitution_path
        self.policy: Dict[str, Any] = {}
        self._initialize_policy()

    def _initialize_policy(self) -> None:
        """Loads and validates the constitution policy file."""
        try:
            if not os.path.exists(self.constitution_path):
                raise FileNotFoundError(f"Constitution file not found at {self.constitution_path}")

            with open(self.constitution_path, "rb") as f:
                content = f.read()
                actual_hash = hashlib.sha256(content).hexdigest()

            if actual_hash != EXPECTED_CONSTITUTION_HASH:
                print(f"CRITICAL ERROR: Policy tamper detected! Hash mismatch.")
                print(f"Expected: {EXPECTED_CONSTITUTION_HASH}")
                print(f"Actual:   {actual_hash}")
                sys.exit(1)

            self.policy = json.loads(content)
        except Exception as e:
            print(f"CRITICAL ERROR: Failed to initialize Sentinel Policy: {e}")
            sys.exit(1)

    def redact_payload(self, payload: str) -> str:
        """Redacts PII and secrets from the payload using regex patterns."""
        redacted_payload = payload
        patterns = self.policy.get("redaction", {}).get("pii_patterns", [])
        
        for p in patterns:
            name = p.get("name", "UNKNOWN")
            regex = p.get("regex", "")
            if regex:
                # Use [REDACTED_NAME] for better auditability
                redacted_payload = re.sub(regex, f"[REDACTED_{name}]", redacted_payload)
        
        return redacted_payload

    def evaluate_intent(self, command: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Evaluates a command against the policy.
        Returns (is_allowed, reason).
        """
        start_time = time.perf_counter()
        
        try:
            # 1. Redact and Log the intent first
            redacted_cmd = self.redact_payload(command)
            
            # 2. Check for dangerous structural patterns (directory traversal, etc.)
            if ".." in command:
                return False, f"BLOCKED: Dangerous path traversal detected in '{redacted_cmd}'"

            # 3. Check for restricted system paths
            restricted_paths = self.policy.get("rules", {}).get("restricted_paths", [])
            for path in restricted_paths:
                if path in command:
                    # Allow read-only access to some paths if explicitly in allow list? 
                    # No, requirement says "modifications to restricted paths", 
                    # but also "identifies high-risk operations including... absolute path overrides".
                    # For safety, block any mention of restricted paths in command strings unless they are benign.
                    # Actually, let's be strict: if it touches a restricted path, it's blocked.
                    return False, f"BLOCKED: Access to restricted system path '{path}' detected"

            # 4. Check against explicit Deny list
            deny_list = self.policy.get("rules", {}).get("denied_commands", [])
            for pattern in deny_list:
                if re.search(pattern, command):
                    return False, f"BLOCKED: Command matches restricted pattern '{pattern}'"

            # 5. Check against explicit Allow list
            allow_list = self.policy.get("rules", {}).get("allowed_commands", [])
            is_allowed = False
            for pattern in allow_list:
                if re.match(pattern, command):
                    is_allowed = True
                    break
            
            # 6. Fail-safe timeout check
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if elapsed_ms > MAX_EVALUATION_TIME_MS:
                return False, f"BLOCKED: Evaluation timeout exceeded ({elapsed_ms:.2f}ms > {MAX_EVALUATION_TIME_MS}ms)"

            if not is_allowed:
                return False, f"BLOCKED: Default-deny - No matching allow rule for '{redacted_cmd}'"

            return True, "ALLOWED"

        except Exception as e:
            return False, f"BLOCKED: Internal evaluation error - {str(e)}"
        finally:
            # Audit logging
            status = "ALLOWED" if 'is_allowed' in locals() and is_allowed else "BLOCKED"
            logging.info(f"Intent: {self.redact_payload(command)} | Status: {status} | Latency: {(time.perf_counter() - start_time)*1000:.2f}ms")

def run_self_tests():
    """Executes the standalone self-test routine."""
    print("=== Sentinel-Policy Self-Test Suite ===")
    
    try:
        sentinel = SentinelPolicy()
        print("[PASS] Policy Initialization & Hash Validation")
    except Exception as e:
        print(f"[FAIL] Policy Initialization: {e}")
        sys.exit(1)

    test_cases = [
        # (Command, Expected Allowed, Test Description)
        ("ls -la", True, "Basic allowed command"),
        ("pwd", True, "Simple allowed command"),
        ("rm -rf /", False, "Dangerous command (destructive)"),
        ("cat /etc/shadow", False, "Restricted path access"),
        ("curl http://malicious.com", False, "Unauthorized network egress"),
        ("git status", True, "Git operation"),
        ("python3 -m unittest discover", True, "Test execution"),
        ("echo AKIA1234567890ABCDEF", False, "Payload containing PII (redaction test)"),
        ("../../etc/passwd", False, "Directory traversal"),
    ]

    failed_tests = 0
    for cmd, expected, desc in test_cases:
        is_allowed, reason = sentinel.evaluate_intent(cmd)
        
        # Verify redaction in reason if applicable
        if "AKIA" in cmd and "AKIA" in reason:
             print(f"[FAIL] {desc}: Sensitive data not redacted in output reason")
             failed_tests += 1
             continue

        if is_allowed == expected:
            print(f"[PASS] {desc}")
        else:
            print(f"[FAIL] {desc}: Expected {expected}, got {is_allowed} (Reason: {reason})")
            failed_tests += 1

    # Performance Test
    print("\n--- Performance Benchmarking ---")
    start_perf = time.perf_counter()
    iterations = 100
    for _ in range(iterations):
        sentinel.evaluate_intent("ls -la")
    end_perf = time.perf_counter()
    avg_latency = ((end_perf - start_perf) / iterations) * 1000
    print(f"Average Latency over {iterations} runs: {avg_latency:.4f}ms")
    
    if avg_latency < 50:
        print(f"[PASS] Performance within target (<50ms)")
    else:
        print(f"[FAIL] Performance exceeds target: {avg_latency:.4f}ms")
        failed_tests += 1

    print("\n=== Test Summary ===")
    if failed_tests == 0:
        print("ALL TESTS PASSED")
        sys.exit(0)
    else:
        print(f"{failed_tests} TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    # If run directly, execute self-tests
    run_self_tests()
