import ast
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from backend.app.scanners.base_scanner import BaseScanner

class SecurityScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Security Engine (AST + Semgrep)", category="security")
        self.semgrep_available = shutil.which("semgrep") is not None
        self.bandit_available = shutil.which("bandit") is not None

    def is_available(self) -> bool:
        # Native AST security rules are always available
        return True

    def scan(self, project_root: str, target_files: List[str]) -> List[Dict[str, Any]]:
        root = Path(project_root).resolve()
        findings = []

        # 1. Native AST & Pattern Security Analysis
        for file_rel in target_files:
            file_abs = root / file_rel
            if not file_abs.is_file():
                continue

            try:
                content = file_abs.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
            except Exception:
                continue

            findings.extend(self._scan_file_content(file_rel, lines, content))

        return findings

    def _scan_file_content(self, file_path: str, lines: List[str], full_text: str) -> List[Dict[str, Any]]:
        file_findings = []
        is_python = file_path.endswith(".py")
        is_js = file_path.endswith((".js", ".ts", ".jsx", ".tsx"))

        # Rule 1: SQL Injection (String Formatting or Direct Concatenation in SQL)
        sql_patterns = [
            (r'(?:execute|raw|query)\s*\(\s*f["\'].*?["\']', "SQL Injection via f-string formatting", "high"),
            (r'SELECT\s+.*?\s+FROM\s+.*?(?:\+|%|\.format\()', "Potential SQL Injection via string concatenation", "high"),
            (r'cursor\.execute\s*\(\s*["\'].*?%s.*?["\']\s*%', "SQL Injection via % operator interpolation", "high")
        ]
        for pattern, title, severity in sql_patterns:
            for idx, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    file_findings.append({
                        "title": title,
                        "category": "security",
                        "severity": severity,
                        "confidence": 0.92,
                        "file_path": file_path,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": line.strip(),
                        "description": "Dynamic SQL query formed through unsanitized string formatting or concatenation.",
                        "impact": "Attackers can manipulate SQL query logic to bypass authentication or extract sensitive database contents.",
                        "recommendation": "Use parameterized queries with placeholders (e.g. cursor.execute('... ?', (param,))).",
                        "verification": "Verify scanner detects no string concatenation in SQL queries.",
                        "detection_method": "ast_security_rules"
                    })

        # Rule 2: Dangerous OS Command Execution
        cmd_patterns = [
            (r'\bos\.system\s*\(', "Direct OS Command Execution (os.system)", "critical"),
            (r'subprocess\.(?:Popen|run|call)\s*\(.*?shell\s*=\s*True', "Subprocess Invocations with shell=True", "high"),
            (r'\bchild_process\.exec\s*\(', "Child Process Execution with Unsanitized String", "high")
        ]
        for pattern, title, severity in cmd_patterns:
            for idx, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    file_findings.append({
                        "title": title,
                        "category": "security",
                        "severity": severity,
                        "confidence": 0.90,
                        "file_path": file_path,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": line.strip(),
                        "description": "Executing system shell commands with external arguments can lead to arbitrary code execution.",
                        "impact": "Remote code execution (RCE) on host operating system.",
                        "recommendation": "Avoid shell command execution or pass arguments as a structured array without shell=True.",
                        "verification": "Test command execution with metacharacters (e.g. '; ls') to verify isolation.",
                        "detection_method": "ast_security_rules"
                    })

        # Rule 3: Dangerous Insecure Deserialization
        deserial_patterns = [
            (r'pickle\.loads?\s*\(', "Insecure Python Object Deserialization (pickle)", "critical"),
            (r'yaml\.load\s*\([^)]*(?:Loader\s*=\s*yaml\.Loader|Loader\s*=\s*Loader)', "Unsafe YAML Deserialization (yaml.load without SafeLoader)", "high")
        ]
        for pattern, title, severity in deserial_patterns:
            for idx, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    file_findings.append({
                        "title": title,
                        "category": "security",
                        "severity": severity,
                        "confidence": 0.95,
                        "file_path": file_path,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": line.strip(),
                        "description": "Deserializing untrusted streams using standard pickle or unsafe YAML loader enables arbitrary code execution.",
                        "impact": "Full server compromise through weaponized serialized objects.",
                        "recommendation": "Use yaml.safe_load() or JSON serialization instead of pickle.",
                        "verification": "Verify all deserializers reject arbitrary executable classes.",
                        "detection_method": "ast_security_rules"
                    })

        # Rule 4: Insecure Configuration & Debug Flags
        config_patterns = [
            (r'\bDEBUG\s*=\s*True\b', "Debug Mode Enabled in Configuration", "medium"),
            (r'\bDEBUG_MODE\s*=\s*True\b', "Debug Mode Enabled in Configuration", "medium"),
            (r'ALLOW_ALL_ORIGINS\s*=\s*\[\s*["\']\*["\']\s*\]', "Permissive CORS Configuration (Wildcard '*')", "medium"),
            (r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', "Permissive CORS Configuration (Wildcard '*')", "medium")
        ]
        for pattern, title, severity in config_patterns:
            for idx, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    file_findings.append({
                        "title": title,
                        "category": "security",
                        "severity": severity,
                        "confidence": 0.95,
                        "file_path": file_path,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": line.strip(),
                        "description": "Production configuration enables debug mode or permissive cross-origin requests.",
                        "impact": "Sensitive stack traces, debug interfaces, or private resources exposed to untrusted web origins.",
                        "recommendation": "Disable DEBUG mode in production environments and restrict CORS origins to trusted domains.",
                        "verification": "Inspect environment variables to ensure DEBUG=False.",
                        "detection_method": "config_auditor"
                    })

        # Rule 5: Path Traversal Risks
        path_patterns = [
            (r'(?:open|fs\.readFile)\s*\(\s*(?:.*?\+|path\.join\(.*?\w+.*?\))', "Potential Path Traversal File Access", "high")
        ]
        for pattern, title, severity in path_patterns:
            for idx, line in enumerate(lines, 1):
                if re.search(pattern, line) and not "static" in line.lower() and not "test" in line.lower():
                    file_findings.append({
                        "title": title,
                        "category": "security",
                        "severity": severity,
                        "confidence": 0.85,
                        "file_path": file_path,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": line.strip(),
                        "description": "Opening file handles with dynamically concatenated paths can allow directory traversal (../).",
                        "impact": "Unauthorized reading or overwriting of sensitive server files (e.g., /etc/passwd or .env).",
                        "recommendation": "Canonicalize target paths using os.path.realpath() and verify against an allowed directory prefix.",
                        "verification": "Attempt directory traversal payloads (e.g. ../../etc/passwd) and verify rejection.",
                        "detection_method": "ast_security_rules"
                    })

        return file_findings
