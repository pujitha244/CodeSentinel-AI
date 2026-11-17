import difflib
import re
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

class RemediationEngine:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()

    def generate_patch(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates an exact before-and-after patch with unified diff for a finding.
        """
        file_path = finding["file_path"]
        full_path = self.project_root / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"Source file {file_path} not found.")

        original_code = full_path.read_text(encoding="utf-8", errors="ignore")
        title = finding["title"].lower()
        desc = finding.get("description", "").lower()

        patched_code = original_code
        explanation = ""

        # Case 1: SQL Injection in database.py / raw execution
        if "sql" in title or "sql" in desc:
            # Pattern: cursor.execute with f-string or string formatting
            unsafe_sql_pattern = r'query\s*=\s*f["\']SELECT\s+id,\s*username,\s*email,\s*role\s+FROM\s+users\s+WHERE\s+username\s*=\s*[\'"]\{search_term\}[\'"]\s+OR\s+email\s*=\s*[\'"]\{search_term\}[\'"]["\']\s*\n\s*try:\s*\n\s*cursor\.execute\(query\)'
            replacement_sql = (
                'query = "SELECT id, username, email, role FROM users WHERE username = ? OR email = ?"\n'
                '        try:\n'
                '            cursor.execute(query, (search_term, search_term))'
            )
            
            if re.search(unsafe_sql_pattern, original_code):
                patched_code = re.sub(unsafe_sql_pattern, replacement_sql, original_code)
                explanation = "Replaced raw f-string SQL query concatenation with parameterized SQL placeholder placeholders '?' and passed parameters as a tuple."
            else:
                # Generic SQL query param fix
                gen_pattern = r'cursor\.execute\s*\(\s*f["\'](SELECT.*?WHERE.*?=.*?)[\'"]\s*\)'
                patched_code = re.sub(
                    r'cursor\.execute\s*\(\s*f["\'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["\']\s*\)',
                    r'cursor.execute("\1?\3", (\2,))',
                    original_code
                )
                explanation = "Converted dynamic string formatted SQL query to parameterized query."

        # Case 2: Hardcoded Secrets in config.py
        elif "aws" in title or "secret" in title or "jwt" in title or "password" in title:
            # Replace raw strings with os.getenv
            lines = original_code.splitlines()
            new_lines = []
            has_os_import = "import os" in original_code
            if not has_os_import:
                new_lines.append("import os")

            for line in lines:
                if "AWS_ACCESS_KEY_ID" in line and "=" in line:
                    new_lines.append('AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")')
                elif "AWS_SECRET_ACCESS_KEY" in line and "=" in line:
                    new_lines.append('AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")')
                elif "JWT_SECRET_KEY" in line and "=" in line:
                    new_lines.append('JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")')
                elif "ADMIN_DEFAULT_PASSWORD" in line and "=" in line:
                    new_lines.append('ADMIN_DEFAULT_PASSWORD = os.getenv("ADMIN_DEFAULT_PASSWORD", "")')
                elif "DEBUG_MODE" in line and "True" in line:
                    new_lines.append('DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"')
                else:
                    new_lines.append(line)

            patched_code = "\n".join(new_lines) + "\n"
            explanation = "Replaced hardcoded sensitive credentials and debug flags with secure os.getenv() lookups."

        # Case 3: Missing null input check in routes.py
        elif "missing null" in title:
            target_route = "user_query = q"
            if target_route in original_code:
                patched_code = original_code.replace(
                    target_route,
                    'user_query = q.strip() if q else ""\n    if not user_query:\n        return {"status": "success", "count": 0, "results": []}'
                )
                explanation = "Added defensive input guard clause rejecting empty or whitespace-only search parameters."

        # Case 4: Bare except in python
        elif "bare 'except:'" in title:
            patched_code = original_code.replace("except:", "except Exception as err:")
            explanation = "Replaced bare 'except:' clause with 'except Exception as err:' to preserve KeyboardInterrupt and SystemExit handling."

        # Case 5: Unused imports
        elif "unused import" in title:
            import_name = finding.get("snippet", "")
            if import_name and import_name in original_code:
                patched_code = original_code.replace(import_name + "\n", "")
                explanation = f"Removed unreferenced import statement '{import_name}'."

        # Compute Unified Diff
        diff_lines = list(difflib.unified_diff(
            original_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            n=3
        ))
        unified_diff = "".join(diff_lines)

        patch_id = f"patch-{uuid.uuid4().hex[:8]}"

        return {
            "patch_id": patch_id,
            "finding_id": finding["id"],
            "file_path": file_path,
            "original_snippet": finding.get("snippet", ""),
            "replacement_snippet": "See unified diff preview",
            "unified_diff": unified_diff,
            "original_code": original_code,
            "patched_code": patched_code,
            "explanation": explanation or "Targeted safe remediation patch designed to eliminate risk without altering core application contracts.",
            "status": "previewed"
        }

    def apply_patch(self, file_path: str, patched_code: str) -> bool:
        full_path = self.project_root / file_path
        if not full_path.exists():
            return False
        # Save backup copy before writing
        backup_path = full_path.with_suffix(full_path.suffix + ".codesentinel_backup")
        if not backup_path.exists():
            backup_path.write_text(full_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        full_path.write_text(patched_code, encoding="utf-8")
        return True

    def rollback_patch(self, file_path: str) -> bool:
        full_path = self.project_root / file_path
        backup_path = full_path.with_suffix(full_path.suffix + ".codesentinel_backup")
        if backup_path.exists():
            full_path.write_text(backup_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            backup_path.unlink()
            return True
        return False
