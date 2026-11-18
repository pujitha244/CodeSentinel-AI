import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

class TaintEngine:
    def __init__(self, project_root: str, parsed_files: Dict[str, Any], call_graph_data: Dict[str, Any]):
        self.project_root = Path(project_root).resolve()
        self.parsed_files = parsed_files
        self.call_graph_data = call_graph_data
        self.functions = call_graph_data.get("functions", {})
        self.edges = call_graph_data.get("edges", [])

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Main entry point for cross-file taint investigation.
        Identifies Sources -> Traces Propagations -> Reaches Sinks.
        Returns a list of verified cross-file VulnerabilityChains.
        """
        chains = []
        sources = self._identify_untrusted_sources()
        sinks = self._identify_dangerous_sinks()

        chain_counter = 1
        for source in sources:
            for sink in sinks:
                path = self._find_tainted_propagation_path(source, sink)
                if path:
                    chain = self._construct_vulnerability_chain(
                        chain_id=f"CS-CHAIN-{chain_counter:04d}",
                        source=source,
                        sink=sink,
                        path=path
                    )
                    chains.append(chain)
                    chain_counter += 1
                elif source["function_key"] == sink["function_key"] and self._sink_reached(
                    sink, set(source["tainted_params"])
                ):
                    chain = self._construct_vulnerability_chain(
                        chain_id=f"CS-CHAIN-{chain_counter:04d}",
                        source=source,
                        sink=sink,
                        path=[]
                    )
                    chains.append(chain)
                    chain_counter += 1

        return chains

    def _identify_untrusted_sources(self) -> List[Dict[str, Any]]:
        """
        Finds functions acting as web API endpoints receiving untrusted input.
        """
        sources = []
        for func_key, func_data in self.functions.items():
            file_path = func_data["file"]
            decorators = func_data.get("decorators", [])
            params = func_data.get("params", [])
            name = func_data["name"]

            # 1. Python FastAPI / Flask routes
            is_route = any(
                any(verb in dec.lower() for verb in ["get", "post", "put", "delete", "route", "patch"])
                for dec in decorators
            ) or name.startswith("ROUTE_") or "endpoint" in name.lower()

            if is_route:
                # Identify tainted parameters (request, query strings, headers, args)
                tainted_params = [
                    p for p in params 
                    if p.lower() not in {"self", "cls", "db", "background_tasks"}
                ]
                
                # Check snippet
                snippet = self._get_snippet(file_path, func_data["start_line"], min(func_data["start_line"] + 4, func_data["end_line"]))
                
                sources.append({
                    "function_key": func_key,
                    "file": file_path,
                    "function": name,
                    "line": func_data["start_line"],
                    "tainted_params": tainted_params or ["query", "input_data"],
                    "snippet": snippet,
                    "type": "api_endpoint",
                    "description": f"Untrusted API input received in '{name}' via request parameters ({', '.join(tainted_params) if tainted_params else 'query parameters'})"
                })

            # 2. JavaScript / Express routes
            elif "router." in " ".join(decorators) or "req" in params:
                snippet = self._get_snippet(file_path, func_data["start_line"], min(func_data["start_line"] + 4, func_data["end_line"]))
                sources.append({
                    "function_key": func_key,
                    "file": file_path,
                    "function": name,
                    "line": func_data["start_line"],
                    "tainted_params": ["req.query", "req.params", "req.body"],
                    "snippet": snippet,
                    "type": "api_endpoint",
                    "description": f"Express route receives untrusted client input in '{name}'"
                })

        return sources

    def _identify_dangerous_sinks(self) -> List[Dict[str, Any]]:
        """
        Finds functions executing dangerous sinks:
        - Raw SQL execution with string interpolation/concatenation
        - Command execution (os.system, subprocess)
        - Arbitrary file reads / path traversal (open, readFile)
        """
        sinks = []
        for func_key, func_data in self.functions.items():
            file_path = func_data["file"]
            lines = self._get_file_lines(file_path)

            for line_no in range(func_data["start_line"], func_data["end_line"] + 1):
                if line_no > len(lines):
                    break
                line_text = lines[line_no - 1]

                # 1. SQL Injection Sink
                sql_sink_match = re.search(r'(?:cursor\.)?execute(?:_raw)?\s*\(\s*(?:f[\'"].*?[\'"]|.*?\%|.*?\.format\(|.*?\+)', line_text)
                raw_sql_str = re.search(r'query\s*=\s*f[\'"].*?(SELECT|INSERT|UPDATE|DELETE).*?[\'"]', line_text, re.IGNORECASE)
                
                if sql_sink_match or raw_sql_str:
                    snippet = self._get_snippet(file_path, max(1, line_no - 2), min(len(lines), line_no + 2))
                    sinks.append({
                        "function_key": func_key,
                        "file": file_path,
                        "function": func_data["name"],
                        "line": line_no,
                        "vulnerability_type": "sql_injection",
                        "title": "SQL Injection in Raw Query Execution",
                        "snippet": snippet,
                        "sink_expression": line_text.strip(),
                        "tainted_variables": sorted(self._expression_names(line_text)),
                        "description": "Constructs and executes an unparameterized SQL statement using dynamic string interpolation with untrusted input.",
                        "remediation": "Replace dynamic string interpolation with parameterized queries or an ORM."
                    })

                # 2. Path Traversal Sink
                path_sink_match = re.search(r'(?:fs\.readFile|open|path\.join)\s*\([^\)]*[\'"].*?uploads.*?[\'"].*?,?\s*(\w+)', line_text)
                if path_sink_match and "read" in line_text.lower():
                    snippet = self._get_snippet(file_path, max(1, line_no - 2), min(len(lines), line_no + 2))
                    sinks.append({
                        "function_key": func_key,
                        "file": file_path,
                        "function": func_data["name"],
                        "line": line_no,
                        "vulnerability_type": "path_traversal",
                        "title": "Path Traversal via Unvalidated File Access",
                        "snippet": snippet,
                        "sink_expression": line_text.strip(),
                        "tainted_variables": sorted(self._expression_names(line_text)),
                        "description": "Accesses local filesystem resources using unvalidated user-controlled file paths.",
                        "remediation": "Validate paths against a strict whitelist and ensure target resides within canonical directory boundaries."
                    })

                # 3. Command Injection Sink
                cmd_match = re.search(r'(?:os\.system|subprocess\.Popen|subprocess\.run|exec|eval)\s*\([^\)]*(?:\+|f[\'"]|%|format)', line_text)
                if cmd_match:
                    snippet = self._get_snippet(file_path, max(1, line_no - 2), min(len(lines), line_no + 2))
                    sinks.append({
                        "function_key": func_key,
                        "file": file_path,
                        "function": func_data["name"],
                        "line": line_no,
                        "vulnerability_type": "command_injection",
                        "title": "OS Command Injection via Shell Execution",
                        "snippet": snippet,
                        "sink_expression": line_text.strip(),
                        "tainted_variables": sorted(self._command_argument_names(line_text)),
                        "description": "Executes shell commands with user-supplied arguments without escaping.",
                        "remediation": "Avoid invoking shell commands with user input, or use parameterized argument lists without shell=True."
                    })

        return sinks

    def _find_tainted_propagation_path(
        self, source: Dict[str, Any], sink: Dict[str, Any]
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Finds a call path only when tainted arguments reach each callee parameter.
        """
        start_key = source["function_key"]
        end_key = sink["function_key"]
        queue = [(start_key, set(source["tainted_params"]), [])]
        visited = set()
        while queue:
            node, tainted_names, path = queue.pop(0)
            state = (node, frozenset(tainted_names))
            if state in visited:
                continue
            visited.add(state)

            if node == end_key and path and self._sink_reached(sink, tainted_names):
                return path

            for edge in self.edges:
                if edge["caller_key"] != node:
                    continue

                caller_taint = self._tainted_variables_at(
                    node, tainted_names, edge["line"], sink["vulnerability_type"]
                )
                callee_taint = self._tainted_callee_parameters(edge, caller_taint)
                if not callee_taint:
                    continue

                next_path = path + [edge]
                callee_key = edge["callee_key"]
                if callee_key == end_key and self._sink_reached(sink, callee_taint):
                    return next_path
                queue.append((callee_key, callee_taint, next_path))

        return None

    def _tainted_callee_parameters(
        self, edge: Dict[str, Any], caller_taint: Set[str]
    ) -> Set[str]:
        callee = self.functions.get(edge["callee_key"], {})
        params = [p for p in callee.get("params", []) if p not in {"self", "cls"}]
        tainted = set()
        positional_index = 0

        for argument in edge.get("args", []):
            keyword_match = re.match(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", argument)
            if keyword_match:
                param_name, expression = keyword_match.groups()
                if param_name in params and self._expression_names(expression) & caller_taint:
                    tainted.add(param_name)
                continue

            if positional_index < len(params) and self._expression_names(argument) & caller_taint:
                tainted.add(params[positional_index])
            positional_index += 1

        return tainted

    def _tainted_variables_at(
        self,
        function_key: str,
        initial_taint: Set[str],
        line: int,
        vulnerability_type: Optional[str] = None,
    ) -> Set[str]:
        tainted = set(initial_taint)
        function = self.functions.get(function_key, {})
        assignments = sorted(
            function.get("assignments", []), key=lambda assignment: assignment.get("line", 0)
        )

        for assignment in assignments:
            if assignment.get("line", 0) > line:
                break
            bindings = assignment.get("bindings") or [
                {"target": target, "value": assignment.get("value", "")}
                for target in assignment.get("targets", [])
            ]
            for binding in bindings:
                target_name = binding.get("target", "")
                if not target_name:
                    continue
                is_sanitized = (
                    vulnerability_type == "command_injection"
                    and self._is_shell_quoted(binding.get("value", ""), tainted)
                )
                is_tainted = (
                    not is_sanitized
                    and bool(self._expression_names(binding.get("value", "")) & tainted)
                )
                if is_tainted:
                    tainted.add(target_name)
                elif not assignment.get("conditional", False):
                    tainted.discard(target_name)

        return tainted

    def _sink_reached(self, sink: Dict[str, Any], tainted_names: Set[str]) -> bool:
        sink_taint = self._tainted_variables_at(
            sink["function_key"],
            tainted_names,
            sink["line"],
            sink.get("vulnerability_type"),
        )
        expression_names = set(sink.get("tainted_variables", []))
        return bool(expression_names & sink_taint)

    @classmethod
    def _is_shell_quoted(cls, expression: str, tainted_names: Set[str]) -> bool:
        unquoted_names, has_quote = cls._shell_expression_facts(expression)
        return has_quote and not (unquoted_names & tainted_names)

    @classmethod
    def _shell_expression_facts(cls, expression: str) -> tuple[Set[str], bool]:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError:
            return cls._expression_names(expression), False

        class ShellExpressionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.names: Set[str] = set()
                self.has_quote = False

            def visit_Name(self, node: ast.Name):
                self.names.add(node.id)

            def visit_Call(self, node: ast.Call):
                is_quote = (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "shlex"
                    and node.func.attr == "quote"
                )
                if is_quote:
                    self.has_quote = True
                    return
                self.generic_visit(node)

        visitor = ShellExpressionVisitor()
        visitor.visit(tree)
        return visitor.names, visitor.has_quote

    @classmethod
    def _command_argument_names(cls, expression: str) -> Set[str]:
        expression = expression.strip()
        try:
            tree = ast.parse(expression)
        except SyntaxError:
            return cls._expression_names(expression)

        names: Set[str] = set()
        found_sink = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            is_dangerous = (
                isinstance(function, ast.Name)
                and function.id in {"exec", "eval"}
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr in {"system", "Popen", "run"}
            )
            if not is_dangerous:
                continue
            found_sink = True
            values = [*node.args, *(keyword.value for keyword in node.keywords)]
            for value in values:
                unquoted_names, _ = cls._shell_expression_facts(ast.unparse(value))
                names.update(unquoted_names)
        return names if found_sink else cls._expression_names(expression)

    @staticmethod
    def _expression_names(expression: str) -> Set[str]:
        try:
            tree = ast.parse(expression, mode="eval")
            return {
                node.id for node in ast.walk(tree)
                if isinstance(node, ast.Name)
            }
        except SyntaxError:
            return set(re.findall(r"\b[A-Za-z_]\w*\b", expression))

    def _construct_vulnerability_chain(
        self, chain_id: str, source: Dict[str, Any], sink: Dict[str, Any], path: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesizes a complete cross-file vulnerability chain with React Flow nodes & edges.
        """
        nodes = []
        edges = []
        node_idx = 0

        # 1. Source Node
        source_node_id = f"node-{node_idx}"
        nodes.append({
            "id": source_node_id,
            "type": "sourceNode",
            "data": {
                "label": f"Input Source: {source['function']}()",
                "kind": "source",
                "file": source["file"],
                "line": source["line"],
                "snippet_start_line": source["line"],
                "function": source["function"],
                "snippet": source["snippet"],
                "description": source["description"],
                "is_tainted": True,
                "badge": "UNTRUSTED SOURCE",
                "badgeColor": "red"
            },
            "position": {"x": 50, "y": 150}
        })
        node_idx += 1

        prev_node_id = source_node_id
        x_pos = 50 + 260
        y_pos = 150

        # 2. Intermediate Propagation Nodes
        for step_edge in path:
            curr_node_id = f"node-{node_idx}"
            callee_func_data = self.functions.get(step_edge["callee_key"], {})
            callee_file = step_edge["callee_file"]
            callee_func = step_edge["callee_func"]
            line = callee_func_data.get("start_line", step_edge["line"])
            
            # The sink is shown separately below at its actual evidence line.
            is_sink_node = (step_edge["callee_key"] == sink["function_key"])

            if not is_sink_node:
                snippet = self._get_snippet(callee_file, line, min(line + 4, callee_func_data.get("end_line", line + 4)))
                nodes.append({
                    "id": curr_node_id,
                    "type": "intermediateNode",
                    "data": {
                        "label": f"Propagates: {callee_func}()",
                        "kind": "intermediate",
                        "file": callee_file,
                        "line": line,
                        "snippet_start_line": line,
                        "function": callee_func,
                        "snippet": snippet,
                        "description": f"Tainted argument(s) {', '.join(step_edge['args'])} reach this function; sanitizer handling is limited.",
                        "is_tainted": True,
                        "badge": "INTERMEDIATE FLOW",
                        "badgeColor": "amber"
                    },
                    "position": {"x": x_pos, "y": y_pos}
                })
                
                # Directed edge
                edges.append({
                    "id": f"flow-e-{node_idx}",
                    "source": prev_node_id,
                    "target": curr_node_id,
                    "label": f"passes ({', '.join(step_edge['args'])})",
                    "animated": True,
                    "type": "smoothstep",
                    "style": {"stroke": "#f59e0b", "strokeWidth": 2}
                })
                prev_node_id = curr_node_id
                x_pos += 260
                node_idx += 1

        # 3. Dangerous Sink Node
        sink_node_id = f"node-{node_idx}"
        nodes.append({
            "id": sink_node_id,
            "type": "sinkNode",
            "data": {
                "label": f"Dangerous Sink: {sink['title']}",
                "kind": "sink",
                "file": sink["file"],
                "line": sink["line"],
                "snippet_start_line": max(1, sink["line"] - 2),
                "function": sink["function"],
                "snippet": sink["snippet"],
                "description": sink["description"],
                "is_tainted": True,
                "badge": "VULNERABLE SINK",
                "badgeColor": "red"
            },
            "position": {"x": x_pos, "y": y_pos}
        })
        sink_call = path[-1] if path else None
        edges.append({
            "id": f"flow-e-{node_idx}",
            "source": prev_node_id,
            "target": sink_node_id,
            "label": (
                f"passes ({', '.join(sink_call['args'])})"
                if sink_call else "same-function data flow"
            ),
            "animated": True,
            "style": {"stroke": "#ef4444", "strokeWidth": 2}
        })

        statically_bound = all(
            edge.get("relationship_type") == "statically_verified" for edge in path
        )
        confidence = 0.94 if path and statically_bound else 0.86 if path else 0.88

        return {
            "id": chain_id,
            "title": f"Cross-File {sink['title']} Chain",
            "vulnerability_type": sink["vulnerability_type"],
            "severity": "critical",
            "confidence": confidence,
            "source_file": source["file"],
            "source_line": source["line"],
            "sink_file": sink["file"],
            "sink_line": sink["line"],
            "description": f"Untrusted input from '{source['file']}:{source['line']}' is passed through {len(path)} call transition(s) and appears in the dynamic expression at '{sink['file']}:{sink['line']}'.",
            "remediation_summary": sink["remediation"],
            "verified": True,
            "nodes": nodes,
            "edges": edges
        }

    def _get_file_lines(self, rel_path: str) -> List[str]:
        full_path = self.project_root / rel_path
        if full_path.exists() and full_path.is_file():
            try:
                return full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                return []
        return []

    def _get_snippet(self, rel_path: str, start_line: int, end_line: int) -> str:
        lines = self._get_file_lines(rel_path)
        if not lines:
            return ""
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        return "\n".join(lines[start:end])
