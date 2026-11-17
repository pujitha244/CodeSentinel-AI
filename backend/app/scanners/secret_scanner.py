import re
from pathlib import Path
from typing import List, Dict, Any
from backend.app.scanners.base_scanner import BaseScanner

class SecretScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Secret Sentinel (Gitleaks Engine)", category="secret")

    def is_available(self) -> bool:
        return True

    def scan(self, project_root: str, target_files: List[str]) -> List[Dict[str, Any]]:
        root = Path(project_root).resolve()
        findings = []

        secret_rules = [
            (
                "AWS Access Key ID",
                r'\b(AKIA[0-9A-Z]{16})\b',
                "critical",
                "Hardcoded AWS Access Key ID exposed in source code."
            ),
            (
                "AWS Secret Access Key",
                r'(?i)aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
                "critical",
                "Hardcoded AWS Secret Access Key exposed in source code."
            ),
            (
                "Hardcoded JWT Secret Token",
                r'(?i)(?:jwt_secret|jwt_secret_key|secret_key)\s*=\s*["\']([^"\']{16,})["\']',
                "high",
                "JWT signing secret stored directly in source code instead of environment variables."
            ),
            (
                "Slack Bot / User Token",
                r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b',
                "high",
                "Hardcoded Slack API authentication token detected."
            ),
            (
                "RSA / OpenSSH Private Key",
                r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                "critical",
                "Unencrypted cryptographic private key embedded in repository."
            ),
            (
                "Hardcoded Database Password",
                r'(?i)(?:password|admin_password|db_pass)\s*=\s*["\']([^"\']{6,})["\']',
                "high",
                "Plaintext database administrative password stored in source file."
            )
        ]

        for file_rel in target_files:
            file_abs = root / file_rel
            if not file_abs.is_file():
                continue

            try:
                lines = file_abs.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, 1):
                # Skip comments explaining rules or test placeholders if explicitly marked mock
                if "fake" in line.lower() and "test" in line.lower() and "key" in line.lower():
                    pass # Still check if it's in config or sample project
                for title, pattern, severity, desc in secret_rules:
                    match = re.search(pattern, line)
                    if match:
                        raw_match = match.group(0)
                        # Redact secret value for display safety
                        redacted_snippet = self._redact(line)
                        findings.append({
                            "title": title,
                            "category": "secret",
                            "severity": severity,
                            "confidence": 0.98,
                            "file_path": file_rel,
                            "start_line": idx,
                            "end_line": idx,
                            "snippet": redacted_snippet,
                            "description": desc,
                            "impact": "Credentials exposed in source repositories can be harvested to gain unauthorized access to cloud services, databases, and APIs.",
                            "recommendation": "Revoke the exposed credential immediately. Store secrets in environment variables or an enterprise secret manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
                            "verification": "Check git history and environment configuration to ensure secret has been rotated and removed.",
                            "detection_method": "secret_sentinel"
                        })

        return findings

    def _redact(self, line: str) -> str:
        # Redact strings inside quotes if long
        return re.sub(r'([\'"])(?:[A-Za-z0-9/+=]{8,})([\'"])', r'\1[REDACTED_SECRET]\2', line.strip())
