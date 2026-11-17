import re
from pathlib import Path
from typing import List, Dict, Any

class LooseEndsEngine:
    def __init__(self, project_root: str, parsed_files: Dict[str, Any], call_graph_data: Dict[str, Any]):
        self.project_root = Path(project_root).resolve()
        self.parsed_files = parsed_files
        self.function_registry = call_graph_data.get("functions", {})

    def analyze(self) -> List[Dict[str, Any]]:
        loose_ends = []
        loose_ends.extend(self._find_comment_markers())
        loose_ends.extend(self._find_placeholder_functions())
        loose_ends.extend(self._find_not_implemented_errors())
        return loose_ends

    def _find_comment_markers(self) -> List[Dict[str, Any]]:
        markers = ["TODO", "FIXME", "HACK", "XXX", "OPTIMIZE", "BUG"]
        results = []

        for file_path in self.parsed_files.keys():
            full_path = self.project_root / file_path
            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                for line_idx, line in enumerate(lines, 1):
                    for marker in markers:
                        # Match comment pattern: # TODO: ... or // FIXME: ...
                        pattern = rf'(?:#|//|/\*)\s*({marker})\s*[:\-]?\s*(.*)'
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            tag = match.group(1).upper()
                            detail = match.group(2).strip() or "Incomplete task annotation"
                            results.append({
                                "title": f"Unresolved {tag}: {detail[:60]}",
                                "category": "loose_end",
                                "severity": "low" if tag == "TODO" else ("medium" if tag == "FIXME" else "info"),
                                "confidence": 0.99,
                                "file_path": file_path,
                                "start_line": line_idx,
                                "end_line": line_idx,
                                "snippet": line.strip(),
                                "description": f"Code contains an unresolved engineering tag '{tag}': {detail}",
                                "impact": "Deferred debt, incomplete feature behavior, or known bug left unaddressed.",
                                "recommendation": f"Resolve the referenced task or track it in a formalized issue tracker before production deployment.",
                                "detection_origin": "Loose End Comment Scanner"
                            })
            except Exception:
                continue

        return results

    def _find_placeholder_functions(self) -> List[Dict[str, Any]]:
        results = []
        for func_key, func_data in self.function_registry.items():
            file_path = func_data["file"]
            full_path = self.project_root / file_path
            if not full_path.exists():
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                start = func_data["start_line"]
                end = func_data["end_line"]
                
                # Check if body consists solely of 'pass', '...', or 'return None'
                body_lines = [
                    l.strip() for l in lines[start:end] 
                    if l.strip() and not l.strip().startswith("#") and not l.strip().startswith('"""') and not l.strip().startswith("'''")
                ]
                
                if len(body_lines) == 1 and body_lines[0] in ["pass", "...", "return None", "return;"]:
                    results.append({
                        "title": f"Empty Placeholder Function '{func_data['name']}'",
                        "category": "loose_end",
                        "severity": "medium",
                        "confidence": 0.95,
                        "file_path": file_path,
                        "start_line": func_data["start_line"],
                        "end_line": func_data["end_line"],
                        "snippet": f"def {func_data['name']}(...):\n    {body_lines[0]}",
                        "description": f"Function '{func_data['name']}' has no functional implementation and contains only a stub '{body_lines[0]}'.",
                        "impact": "Calling this function has no effect, potentially leading to silent failures or unhandled business logic.",
                        "recommendation": "Implement the expected business logic or remove the stub if obsolete.",
                        "detection_origin": "Stub & Placeholder Detector"
                    })
            except Exception:
                continue

        return results

    def _find_not_implemented_errors(self) -> List[Dict[str, Any]]:
        results = []
        for func_key, func_data in self.function_registry.items():
            file_path = func_data["file"]
            full_path = self.project_root / file_path
            if not full_path.exists():
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                body_lines = lines[func_data["start_line"] - 1:func_data["end_line"]]
                for idx, line in enumerate(body_lines, func_data["start_line"]):
                    if "raise NotImplementedError" in line or "throw new Error('Not implemented')" in line:
                        results.append({
                            "title": f"Unimplemented Method in '{func_data['name']}'",
                            "category": "loose_end",
                            "severity": "high",
                            "confidence": 0.98,
                            "file_path": file_path,
                            "start_line": idx,
                            "end_line": idx,
                            "snippet": line.strip(),
                            "description": f"Function '{func_data['name']}' explicitly raises NotImplementedError when invoked in runtime paths.",
                            "impact": "Immediate runtime exception crashing downstream execution if invoked.",
                            "recommendation": "Complete the implementation or guard call sites with feature flags.",
                            "detection_origin": "NotImplemented Sentinel"
                        })
            except Exception:
                continue

        return results
