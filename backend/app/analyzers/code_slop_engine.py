import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

class CodeSlopEngine:
    def __init__(self, project_root: str, parsed_files: Dict[str, Any], call_graph_data: Dict[str, Any]):
        self.project_root = Path(project_root).resolve()
        self.parsed_files = parsed_files
        self.call_graph_data = call_graph_data
        self.function_registry = call_graph_data.get("functions", {})
        self.edges = call_graph_data.get("edges", [])

    def analyze(self) -> Dict[str, Any]:
        unused_imports = self._find_unused_imports()
        dead_functions = self._find_dead_functions()
        duplicate_blocks = self._find_duplicate_blocks()
        complexity_hotspots = self._find_complexity_hotspots()

        # Calculate Code Slop Score (0 - 100, where 0 is pristine and 100 is pure slop)
        deductions = []
        slop_score = 0.0

        if unused_imports:
            penalty = min(25.0, len(unused_imports) * 5.0)
            slop_score += penalty
            deductions.append({
                "category": "Unused Imports",
                "count": len(unused_imports),
                "penalty": penalty,
                "explanation": f"Found {len(unused_imports)} unreferenced imported modules cluttering the namespace."
            })

        if dead_functions:
            penalty = min(30.0, len(dead_functions) * 10.0)
            slop_score += penalty
            deductions.append({
                "category": "Dead / Unreferenced Functions",
                "count": len(dead_functions),
                "penalty": penalty,
                "explanation": f"Found {len(dead_functions)} functions that are never called across the codebase."
            })

        if duplicate_blocks:
            penalty = min(25.0, len(duplicate_blocks) * 12.5)
            slop_score += penalty
            deductions.append({
                "category": "Duplicate Logic Blocks",
                "count": len(duplicate_blocks),
                "penalty": penalty,
                "explanation": f"Found {len(duplicate_blocks)} identical or near-identical code blocks across modules."
            })

        if complexity_hotspots:
            penalty = min(20.0, len(complexity_hotspots) * 5.0)
            slop_score += penalty
            deductions.append({
                "category": "Excessive Complexity / Deep Nesting",
                "count": len(complexity_hotspots),
                "penalty": penalty,
                "explanation": f"Found {len(complexity_hotspots)} functions with high cyclomatic complexity or deep nesting."
            })

        slop_score = round(min(100.0, slop_score), 1)

        return {
            "slop_score": slop_score,
            "quality_rating": "Clean" if slop_score < 20 else ("Moderate Slop" if slop_score < 50 else "High Slop"),
            "deductions": deductions,
            "unused_imports": unused_imports,
            "dead_functions": dead_functions,
            "duplicate_blocks": duplicate_blocks,
            "complexity_hotspots": complexity_hotspots
        }

    def _find_unused_imports(self) -> List[Dict[str, Any]]:
        results = []
        for file_path, file_data in self.parsed_files.items():
            if file_data.get("language") != "python":
                continue
            full_path = self.project_root / file_path
            if not full_path.exists():
                continue
            try:
                code = full_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(code)
            except Exception:
                continue

            # Collect all identifiers used in the code
            used_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store):
                    used_names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name):
                        used_names.add(node.value.id)

            for imp in file_data.get("imports", []):
                name = imp.get("name")
                asname = imp.get("asname") or name
                # Exclude __init__.py exports or special cases
                if "__init__" in file_path:
                    continue
                if asname not in used_names:
                    results.append({
                        "file": file_path,
                        "line": imp.get("line", 1),
                        "import_name": asname,
                        "module": imp.get("module", ""),
                        "snippet": f"import {imp.get('module')}" if imp.get('type') == 'import' else f"from {imp.get('module')} import {name}",
                        "recommendation": f"Remove unused import '{asname}' from {file_path} to reduce namespace pollution."
                    })
        return results

    def _find_dead_functions(self) -> List[Dict[str, Any]]:
        """
        Finds functions that are never called and not routes/endpoints/tests/__init__.
        """
        called_function_names = set()
        for edge in self.edges:
            called_function_names.add(edge["callee_key"])
            called_function_names.add(edge["callee_func"])

        dead = []
        for func_key, func_data in self.function_registry.items():
            name = func_data["name"]
            file_path = func_data["file"]
            decorators = func_data.get("decorators", [])

            # Skip special functions
            if name.startswith("__") or name.startswith("test_") or "test" in file_path.lower():
                continue
            if any(d in " ".join(decorators).lower() for d in ["get", "post", "put", "delete", "route", "property"]):
                continue

            short_name = name.split(".")[-1]
            if func_key not in called_function_names and short_name not in called_function_names:
                dead.append({
                    "file": file_path,
                    "function": name,
                    "line": func_data["start_line"],
                    "end_line": func_data["end_line"],
                    "snippet": f"def {name}({', '.join(func_data['params'])}): ...",
                    "recommendation": f"Function '{name}' appears unused across the project. Review and remove if legacy code."
                })
        return dead

    def _find_duplicate_blocks(self) -> List[Dict[str, Any]]:
        """
        Detects duplicate or near-duplicate function bodies across the project.
        """
        duplicates = []
        seen_bodies: Dict[str, Tuple[str, str, int]] = {}

        for func_key, func_data in self.function_registry.items():
            file_path = func_data["file"]
            full_path = self.project_root / file_path
            if not full_path.exists():
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                start = func_data["start_line"]
                end = func_data["end_line"]
                # Skip trivial 1-2 line getters
                if end - start < 3:
                    continue

                body_lines = [l.strip() for l in lines[start:end] if l.strip() and not l.strip().startswith("#")]
                # Normalize variable names in string representation
                normalized = "\n".join(body_lines)

                if normalized in seen_bodies:
                    orig_file, orig_func, orig_line = seen_bodies[normalized]
                    duplicates.append({
                        "file_a": orig_file,
                        "function_a": orig_func,
                        "line_a": orig_line,
                        "file_b": file_path,
                        "function_b": func_data["name"],
                        "line_b": func_data["start_line"],
                        "line_count": len(body_lines),
                        "snippet": "\n".join(body_lines[:4]) + "\n...",
                        "recommendation": f"Consolidate duplicate logic between '{orig_func}' ({orig_file}) and '{func_data['name']}' ({file_path}) into a shared utility function."
                    })
                else:
                    seen_bodies[normalized] = (file_path, func_data["name"], func_data["start_line"])
            except Exception:
                continue

        return duplicates

    def _find_complexity_hotspots(self) -> List[Dict[str, Any]]:
        hotspots = []
        for func_key, func_data in self.function_registry.items():
            file_path = func_data["file"]
            full_path = self.project_root / file_path
            if not full_path.exists():
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                start = func_data["start_line"] - 1
                end = func_data["end_line"]
                func_lines = lines[start:end]

                complexity = 1
                max_nesting = 0
                for line in func_lines:
                    stripped = line.strip()
                    # Branch statements
                    if re.match(r'^(if|elif|for|while|except|catch)\b', stripped):
                        complexity += 1
                    if " && " in stripped or " and " in stripped or " || " in stripped or " or " in stripped:
                        complexity += 1
                    # Estimate indentation nesting
                    indent = len(line) - len(line.lstrip())
                    nesting = indent // 4
                    if nesting > max_nesting:
                        max_nesting = nesting

                if complexity >= 6 or max_nesting >= 4:
                    hotspots.append({
                        "file": file_path,
                        "function": func_data["name"],
                        "line": func_data["start_line"],
                        "cyclomatic_complexity": complexity,
                        "max_nesting": max_nesting,
                        "recommendation": f"Refactor '{func_data['name']}' (complexity {complexity}, nesting {max_nesting}) by extracting helper functions."
                    })
            except Exception:
                continue

        return hotspots
