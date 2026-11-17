import re
from pathlib import Path
from typing import List, Dict, Any
from backend.app.scanners.base_scanner import BaseScanner

class QualityScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Code Quality & Standards Scanner (Ruff Style)", category="quality")

    def is_available(self) -> bool:
        return True

    def scan(self, project_root: str, target_files: List[str]) -> List[Dict[str, Any]]:
        root = Path(project_root).resolve()
        findings = []

        for file_rel in target_files:
            file_abs = root / file_rel
            if not file_abs.is_file():
                continue

            try:
                lines = file_abs.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, 1):
                stripped = line.strip()

                # Wildcard import (e.g. from module import *)
                if re.match(r'^from\s+[\w\.]+\s+import\s+\*', stripped):
                    findings.append({
                        "title": "Wildcard Import Detected (from ... import *)",
                        "category": "quality",
                        "severity": "low",
                        "confidence": 0.95,
                        "file_path": file_rel,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": stripped,
                        "description": "Wildcard imports pollute the local namespace and obscure where names originate.",
                        "impact": "Namespace collisions, difficult debugging, and IDE auto-complete degradation.",
                        "recommendation": "Import specific symbols explicitly or import the parent module.",
                        "verification": "Verify no wildcard '*' imports remain.",
                        "detection_method": "quality_standards_checker"
                    })

                # Bare except clause (except:)
                if re.match(r'^except\s*:', stripped):
                    findings.append({
                        "title": "Bare 'except:' Clause Catches SystemExit and KeyboardInterrupt",
                        "category": "quality",
                        "severity": "medium",
                        "confidence": 0.95,
                        "file_path": file_rel,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": stripped,
                        "description": "A bare except statement catches all exceptions including KeyboardInterrupt and SystemExit, preventing normal program termination.",
                        "impact": "Masked critical runtime bugs and inability to gracefully exit the application.",
                        "recommendation": "Catch specific exception types (e.g. except Exception as e: or domain exceptions).",
                        "verification": "Confirm except clauses specify Exception subclasses.",
                        "detection_method": "quality_standards_checker"
                    })

                # Extreme line length (> 140 chars)
                if len(line) > 140 and not any(tag in line for tag in ["http://", "https://", "AKIA"]):
                    findings.append({
                        "title": f"Excessive Line Length ({len(line)} characters)",
                        "category": "quality",
                        "severity": "info",
                        "confidence": 0.90,
                        "file_path": file_rel,
                        "start_line": idx,
                        "end_line": idx,
                        "snippet": stripped[:80] + "...",
                        "description": "Line exceeds recommended 120-character maximum, hurting readability and git diff reviews.",
                        "impact": "Reduced code maintainability and team review efficiency.",
                        "recommendation": "Split statements or long arguments across multiple lines.",
                        "verification": "Check line lengths conform to PEP8 / standard formatting.",
                        "detection_method": "quality_standards_checker"
                    })

        return findings
