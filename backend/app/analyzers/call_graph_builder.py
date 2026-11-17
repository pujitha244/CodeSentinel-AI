from typing import Dict, List, Any, Optional
from backend.app.analyzers.import_resolver import ImportResolver

class CallGraphBuilder:
    def __init__(self, project_root: str, parsed_files: Dict[str, Any]):
        self.project_root = project_root
        self.parsed_files = parsed_files
        self.resolver = ImportResolver(project_root)
        
        # Mapping: file_path -> { import_alias: target_file_path }
        self.file_import_maps: Dict[str, Dict[str, str]] = {}
        
        # Mapping: (file_path, func_name) -> function_info
        self.function_registry: Dict[str, Dict[str, Any]] = {}
        
        # Call graph edges: list of { caller: ..., callee: ..., line: ..., args: ... }
        self.edges: List[Dict[str, Any]] = []

    def build(self) -> Dict[str, Any]:
        self._index_functions()
        self._resolve_all_imports()
        self._connect_calls()
        return {
            "functions": self.function_registry,
            "imports": self.file_import_maps,
            "edges": self.edges,
            "architecture_graph": self.get_architecture_graph()
        }

    def _index_functions(self):
        for file_path, file_data in self.parsed_files.items():
            for func in file_data.get("functions", []):
                key = f"{file_path}::{func['name']}"
                self.function_registry[key] = {
                    "file": file_path,
                    "name": func["name"],
                    "params": func["params"],
                    "start_line": func["start_line"],
                    "end_line": func["end_line"],
                    "calls": func["calls"],
                    "assignments": func.get("assignments", []),
                    "decorators": func.get("decorators", [])
                }

    def _resolve_all_imports(self):
        for file_path, file_data in self.parsed_files.items():
            lang = file_data.get("language", "python")
            self.file_import_maps[file_path] = {}
            for imp in file_data.get("imports", []):
                target_file = None
                if lang == "python":
                    target_file = self.resolver.resolve_python_import(
                        file_path, 
                        imp.get("module", ""), 
                        imp.get("name", "")
                    )
                elif lang == "javascript":
                    target_file = self.resolver.resolve_js_import(file_path, imp.get("module", ""))

                if target_file:
                    alias = imp.get("asname") or imp.get("name")
                    self.file_import_maps[file_path][alias] = target_file
                    # Also map module base if applicable
                    self.file_import_maps[file_path][imp.get("module")] = target_file

    def _connect_calls(self):
        for caller_key, func_data in self.function_registry.items():
            caller_file = func_data["file"]
            caller_func = func_data["name"]

            for call in func_data["calls"]:
                call_name = call["name"]
                callee_obj = call["callee_obj"]
                target_func_key = None
                target_file = None
                relationship_type = "statically_verified"

                # 1. Intra-file call
                local_key = f"{caller_file}::{call_name}"
                if local_key in self.function_registry:
                    target_func_key = local_key
                    target_file = caller_file

                # 2. Inter-file call via imported class / instance
                # e.g., UserService.search_users or user_service.search_users
                if not target_func_key and callee_obj:
                    # Check if callee_obj corresponds to an imported module or class
                    # Check direct import map
                    import_file = self.file_import_maps.get(caller_file, {}).get(callee_obj)
                    if not import_file:
                        # Check if callee_obj is an instance of an imported class:
                        # Look at assignments in this function or caller file
                        for assign in func_data.get("assignments", []):
                            if callee_obj in assign.get("targets", []):
                                val = assign.get("value", "")
                                class_name = val.split("(")[0].strip()
                                import_file = self.file_import_maps.get(caller_file, {}).get(class_name)
                                if import_file:
                                    break

                    # Also check class attribute instantiation like self.db = DatabaseManager()
                    if not import_file and "self." in callee_obj:
                        attr_name = callee_obj.replace("self.", "")
                        # Look at __init__ of caller's class
                        class_prefix = caller_func.split(".")[0] if "." in caller_func else ""
                        init_key = f"{caller_file}::{class_prefix}.__init__"
                        if init_key in self.function_registry:
                            init_func = self.function_registry[init_key]
                            for assign in init_func.get("assignments", []):
                                if f"self.{attr_name}" in assign.get("targets", []) or attr_name in assign.get("targets", []):
                                    val = assign.get("value", "")
                                    cls_name = val.split("(")[0].strip()
                                    import_file = self.file_import_maps.get(caller_file, {}).get(cls_name)
                                    if import_file:
                                        break

                    if import_file:
                        # Find matching method in target_file
                        for cand_key, cand_data in self.function_registry.items():
                            if cand_data["file"] == import_file:
                                if cand_data["name"] == call_name or cand_data["name"].endswith(f".{call_name}"):
                                    target_func_key = cand_key
                                    target_file = import_file
                                    break

                # 3. Fallback: match by unique function name across project
                if not target_func_key:
                    matches = [k for k, v in self.function_registry.items() if v["name"] == call_name or v["name"].endswith(f".{call_name}")]
                    if len(matches) == 1:
                        target_func_key = matches[0]
                        target_file = self.function_registry[target_func_key]["file"]
                        relationship_type = "inferred"

                if target_func_key:
                    self.edges.append({
                        "caller_key": caller_key,
                        "caller_file": caller_file,
                        "caller_func": caller_func,
                        "callee_key": target_func_key,
                        "callee_file": target_file,
                        "callee_func": self.function_registry[target_func_key]["name"],
                        "line": call["line"],
                        "args": call["args"],
                        "relationship_type": relationship_type
                    })

    def get_architecture_graph(self) -> Dict[str, Any]:
        """
        Creates a React Flow compatible node and edge graph for the repository.
        """
        nodes = []
        edges = []
        node_ids = set()

        # Add File Nodes
        for idx, file_path in enumerate(self.parsed_files.keys()):
            file_id = f"file-{file_path}"
            node_ids.add(file_id)
            lang = self.parsed_files[file_path].get("language", "text")
            nodes.append({
                "id": file_id,
                "type": "fileNode",
                "data": {
                    "label": file_path,
                    "kind": "file",
                    "language": lang,
                    "functionCount": len(self.parsed_files[file_path].get("functions", [])),
                    "importCount": len(self.parsed_files[file_path].get("imports", []))
                },
                "position": {"x": 100 + (idx % 4) * 260, "y": 80 + (idx // 4) * 160}
            })

        # Add File-to-File Import Edges
        edge_id = 0
        added_edges = set()
        for source_file, imports in self.file_import_maps.items():
            for alias, target_file in imports.items():
                if target_file in self.parsed_files and target_file != source_file:
                    edge_key = f"{source_file}->{target_file}"
                    if edge_key not in added_edges:
                        added_edges.add(edge_key)
                        edges.append({
                            "id": f"e-imp-{edge_id}",
                            "source": f"file-{source_file}",
                            "target": f"file-{target_file}",
                            "label": f"imports ({alias})",
                            "animated": True,
                            "type": "smoothstep",
                            "style": {"stroke": "#6366f1", "strokeWidth": 2}
                        })
                        edge_id += 1

        # Add Cross-file call edges
        for call_edge in self.edges:
            c_src = f"file-{call_edge['caller_file']}"
            c_tgt = f"file-{call_edge['callee_file']}"
            if c_src != c_tgt:
                edge_key = f"call-{call_edge['caller_key']}->{call_edge['callee_key']}"
                if edge_key not in added_edges:
                    added_edges.add(edge_key)
                    edges.append({
                        "id": f"e-call-{edge_id}",
                        "source": c_src,
                        "target": c_tgt,
                        "label": f"{call_edge['caller_func']} -> {call_edge['callee_func']}()",
                        "animated": True,
                        "type": "default",
                        "style": {"stroke": "#ec4899", "strokeDasharray": "5,5", "strokeWidth": 2}
                    })
                    edge_id += 1

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "file_count": len(self.parsed_files),
                "function_count": len(self.function_registry),
                "edge_count": len(edges)
            }
        }
