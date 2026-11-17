import re
from pathlib import Path
from typing import List, Dict, Any

class LogicGapEngine:
    def __init__(self, project_root: str, parsed_files: Dict[str, Any], call_graph_data: Dict[str, Any]):
        self.project_root = Path(project_root).resolve()
        self.parsed_files = parsed_files
        self.function_registry = call_graph_data.get("functions", {})

    def analyze(self) -> List[Dict[str, Any]]:
        gaps = []
        gaps.extend(self._check_missing_null_validation())
        gaps.extend(self._check_boundary_conditions())
        gaps.extend(self._check_unhandled_exceptions())
        gaps.extend(self._check_missing_authorization())
        return gaps

    def _check_missing_null_validation(self) -> List[Dict[str, Any]]:
        gaps = []
        for func_key, func_data in self.function_registry.items():
            params = func_data.get("params", [])
            file_path = func_data["file"]
            lines = self._get_file_lines(file_path)
            
            # If function receives string or user input parameters, inspect if empty/none checks exist
            body_text = "\n".join(lines[func_data["start_line"] - 1:func_data["end_line"]])
            for param in params:
                if param.lower() in ["q", "query", "user_query", "search", "term", "userpath", "filename"]:
                    has_check = any(pattern in body_text for pattern in [
                        f"if not {param}", f"if {param} is None", f"if {param} == ''",
                        f"!{param}", f"{param} === undefined", f"len({param})"
                    ])
                    if not has_check:
                        gaps.append({
                            "title": f"Missing Null / Empty Input Validation for '{param}'",
                            "category": "logic_gap",
                            "severity": "medium",
                            "confidence": 0.88,
                            "file_path": file_path,
                            "start_line": func_data["start_line"],
                            "end_line": min(func_data["start_line"] + 4, func_data["end_line"]),
                            "description": f"Function '{func_data['name']}' accepts parameter '{param}' but does not validate whether it is None, empty string, or whitespace-only before proceeding.",
                            "triggering_scenario": f"An attacker or client submits an empty query string or null payload (e.g., ?q= or {param}: null), leading to unintended database scans or null-pointer crashes.",
                            "impact": "Potential unhandled exceptions, expensive full-table queries, or unexpected state transitions.",
                            "recommendation": f"Add explicit guard clause: if not {param} or not {param}.strip(): raise ValueError('{param} cannot be empty').",
                            "detection_origin": "AST Parameter Flow Inspector"
                        })
        return gaps

    def _check_boundary_conditions(self) -> List[Dict[str, Any]]:
        gaps = []
        for func_key, func_data in self.function_registry.items():
            params = func_data.get("params", [])
            file_path = func_data["file"]
            lines = self._get_file_lines(file_path)
            body_text = "\n".join(lines[func_data["start_line"] - 1:func_data["end_line"]])

            for param in params:
                if param.lower() in ["user_id", "id", "limit", "offset", "page"]:
                    # Check if negative number check or upper bound exists
                    has_boundary = any(pattern in body_text for pattern in [
                        f"{param} <= 0", f"{param} < 0", f"{param} < 1", f"max({param}"
                    ])
                    if not has_boundary:
                        gaps.append({
                            "title": f"Unchecked Numeric Boundary for '{param}'",
                            "category": "logic_gap",
                            "severity": "low",
                            "confidence": 0.82,
                            "file_path": file_path,
                            "start_line": func_data["start_line"],
                            "end_line": min(func_data["start_line"] + 3, func_data["end_line"]),
                            "description": f"Numeric identifier or pagination parameter '{param}' does not verify positive boundary limits or maximum bounds.",
                            "triggering_scenario": f"Passing negative or oversized numbers (e.g. ?user_id=-1 or ?page=-999999999) can trigger database indexing anomalies or resource exhaustion.",
                            "impact": "Inconsistent data retrieval, negative ID lookup anomalies, or denial of service.",
                            "recommendation": f"Validate that {param} >= 1 and cap maximum page size to a safe threshold (e.g. min(limit, 100)).",
                            "detection_origin": "Boundary Condition Engine"
                        })
        return gaps

    def _check_unhandled_exceptions(self) -> List[Dict[str, Any]]:
        gaps = []
        for func_key, func_data in self.function_registry.items():
            file_path = func_data["file"]
            lines = self._get_file_lines(file_path)
            body_text = "\n".join(lines[func_data["start_line"] - 1:func_data["end_line"]])

            # If function executes database or file I/O operations without try...except / try...catch
            io_operations = ["cursor.execute", "sqlite3.connect", "fs.readFile", "open("]
            has_io = any(op in body_text for op in io_operations)
            has_error_handling = "try:" in body_text or "try {" in body_text or "except" in body_text

            if has_io and not has_error_handling:
                gaps.append({
                    "title": f"Unhandled I/O Exception in '{func_data['name']}'",
                    "category": "logic_gap",
                    "severity": "medium",
                    "confidence": 0.85,
                    "file_path": file_path,
                    "start_line": func_data["start_line"],
                    "end_line": func_data["end_line"],
                    "description": f"Function '{func_data['name']}' performs I/O operations but lacks exception handling or error recovery blocks.",
                    "triggering_scenario": "File locks, concurrent database transaction collisions, or missing files will crash the worker process without a structured HTTP error response.",
                    "impact": "500 Internal Server Errors, unhandled application crashes, and resource leakages.",
                    "recommendation": "Wrap the operation in a try/except (or try/catch) block and return a structured domain error.",
                    "detection_origin": "Exception Safety Analyzer"
                })
        return gaps

    def _check_missing_authorization(self) -> List[Dict[str, Any]]:
        gaps = []
        for func_key, func_data in self.function_registry.items():
            name = func_data["name"].lower()
            file_path = func_data["file"]
            lines = self._get_file_lines(file_path)
            body_text = "\n".join(lines[func_data["start_line"] - 1:func_data["end_line"]])
            decorators = " ".join(func_data.get("decorators", [])).lower()

            # Mutating operations
            if any(action in name for action in ["delete", "drop", "update", "admin", "remove"]):
                has_auth = any(auth in body_text.lower() or auth in decorators for auth in [
                    "verify_token", "authenticate", "require_role", "current_user", "is_admin", "jwt"
                ])
                if not has_auth:
                    gaps.append({
                        "title": f"Missing Authorization Check on Mutating Action '{func_data['name']}'",
                        "category": "logic_gap",
                        "severity": "high",
                        "confidence": 0.90,
                        "file_path": file_path,
                        "start_line": func_data["start_line"],
                        "end_line": min(func_data["start_line"] + 4, func_data["end_line"]),
                        "description": f"Dangerous state-modifying action '{func_data['name']}' is exposed without role-based access control or user identity verification.",
                        "triggering_scenario": "Any unauthenticated user or lower-privileged caller can send a request to trigger data deletion or modification.",
                        "impact": "Unauthorized deletion or alteration of application data (IDOR / Broken Access Control).",
                        "recommendation": "Enforce authentication middleware or dependency injection (e.g. Depends(verify_token)) on this route.",
                        "detection_origin": "Authorization Boundary Hunter"
                    })
        return gaps

    def _get_file_lines(self, rel_path: str) -> List[str]:
        full_path = self.project_root / rel_path
        if full_path.exists() and full_path.is_file():
            try:
                return full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                return []
        return []
