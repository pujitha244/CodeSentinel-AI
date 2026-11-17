import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

class FunctionInfo:
    def __init__(self, name: str, params: List[str], start_line: int, end_line: int, 
                 calls: List[Dict[str, Any]], assignments: List[Dict[str, Any]], 
                 is_async: bool = False, decorators: List[str] = None):
        self.name = name
        self.params = params
        self.start_line = start_line
        self.end_line = end_line
        self.calls = calls
        self.assignments = assignments
        self.is_async = is_async
        self.decorators = decorators or []

    def to_dict(self):
        return {
            "name": self.name,
            "params": self.params,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "calls": self.calls,
            "assignments": self.assignments,
            "is_async": self.is_async,
            "decorators": self.decorators
        }


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.imports: List[Dict[str, Any]] = []
        self.functions: List[FunctionInfo] = []
        self.classes: List[Dict[str, Any]] = []
        self.current_function: Optional[FunctionInfo] = None
        self.current_class: Optional[str] = None
        self.raw_calls: List[Dict[str, Any]] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append({
                "module": alias.name,
                "name": alias.asname or alias.name,
                "line": node.lineno,
                "type": "import"
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.imports.append({
                "module": module,
                "name": alias.name,
                "asname": alias.asname or alias.name,
                "line": node.lineno,
                "type": "import_from"
            })
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_class = self.current_class
        self.current_class = node.name
        class_info = {
            "name": node.name,
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "bases": [ast.unparse(b) for b in node.bases] if hasattr(ast, "unparse") else [],
            "methods": []
        }
        self.classes.append(class_info)
        self.generic_visit(node)
        self.current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_func(node, is_async=True)

    def _process_func(self, node, is_async: bool):
        params = [arg.arg for arg in node.args.args]
        decorators = []
        for d in node.decorator_list:
            if hasattr(ast, "unparse"):
                decorators.append(ast.unparse(d))
            elif isinstance(d, ast.Name):
                decorators.append(d.id)
            elif isinstance(d, ast.Attribute):
                decorators.append(f"{ast.unparse(d.value)}.{d.attr}" if hasattr(ast, "unparse") else d.attr)

        func_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        func_info = FunctionInfo(
            name=func_name,
            params=params,
            start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            calls=[],
            assignments=[],
            is_async=is_async,
            decorators=decorators
        )
        
        prev_func = self.current_function
        self.current_function = func_info
        
        # Visit child statements to collect calls and assignments
        for item in node.body:
            self.visit(item)
            
        self.functions.append(func_info)
        if self.current_class and self.classes:
            self.classes[-1]["methods"].append(func_name)
            
        self.current_function = prev_func

    def visit_Call(self, node: ast.Call):
        func_name = ""
        callee_obj = ""
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if hasattr(ast, "unparse"):
                callee_obj = ast.unparse(node.func.value)
            elif isinstance(node.func.value, ast.Name):
                callee_obj = node.func.value.id

        args_repr = []
        for a in node.args:
            if hasattr(ast, "unparse"):
                args_repr.append(ast.unparse(a))
            else:
                args_repr.append(type(a).__name__)

        call_data = {
            "name": func_name,
            "callee_obj": callee_obj,
            "full_call": f"{callee_obj}.{func_name}" if callee_obj else func_name,
            "args": args_repr,
            "line": node.lineno
        }
        
        self.raw_calls.append(call_data)
        if self.current_function:
            self.current_function.calls.append(call_data)
            
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        targets = []
        for t in node.targets:
            if hasattr(ast, "unparse"):
                targets.append(ast.unparse(t))
            elif isinstance(t, ast.Name):
                targets.append(t.id)

        value_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        assignment_data = {
            "targets": targets,
            "value": value_repr,
            "line": node.lineno
        }
        
        if self.current_function:
            self.current_function.assignments.append(assignment_data)
            
        self.generic_visit(node)


class CodeParser:
    @staticmethod
    def parse_python(file_path: str, code: str) -> Dict[str, Any]:
        try:
            tree = ast.parse(code, filename=file_path)
            visitor = PythonASTVisitor(code)
            visitor.visit(tree)
            return {
                "file_path": file_path,
                "language": "python",
                "imports": visitor.imports,
                "functions": [f.to_dict() for f in visitor.functions],
                "classes": visitor.classes,
                "calls": visitor.raw_calls,
                "error": None
            }
        except SyntaxError as e:
            return {
                "file_path": file_path,
                "language": "python",
                "imports": [],
                "functions": [],
                "classes": [],
                "calls": [],
                "error": f"Syntax error at line {e.lineno}: {e.msg}"
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "language": "python",
                "imports": [],
                "functions": [],
                "classes": [],
                "calls": [],
                "error": str(e)
            }

    @staticmethod
    def parse_javascript(file_path: str, code: str) -> Dict[str, Any]:
        """
        Extracts JS/TS functions, imports, calls, and routes.
        """
        lines = code.splitlines()
        imports = []
        functions = []
        calls = []

        # 1. Imports
        import_patterns = [
            (r'const\s+(\w+)\s*=\s*require\([\'"]([^\'"]+)[\'"]\)', "require"),
            (r'import\s+(\w+)\s+from\s+[\'"]([^\'"]+)[\'"]', "esm_default"),
            (r'import\s+\{([^}]+)\}\s+from\s+[\'"]([^\'"]+)[\'"]', "esm_named")
        ]
        
        for idx, line in enumerate(lines, 1):
            for pat, kind in import_patterns:
                for match in re.finditer(pat, line):
                    if kind == "esm_named":
                        names = [n.strip() for n in match.group(1).split(",")]
                        for n in names:
                            imports.append({"name": n, "module": match.group(2), "line": idx, "type": kind})
                    else:
                        imports.append({"name": match.group(1), "module": match.group(2), "line": idx, "type": kind})

        # 2. Functions
        func_patterns = [
            (r'function\s+(\w+)\s*\(([^)]*)\)', "function"),
            (r'const\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>', "arrow"),
            (r'(\w+)\s*:\s*function\s*\(([^)]*)\)', "method"),
            (r'router\.(get|post|put|delete)\s*\([\'"]([^\'"]+)[\'"]\s*,\s*(?:async\s*)?\(([^)]*)\)', "route")
        ]

        for idx, line in enumerate(lines, 1):
            for pat, kind in func_patterns:
                for m in re.finditer(pat, line):
                    if kind == "route":
                        params = [p.strip() for p in m.group(3).split(",") if p.strip()]
                        functions.append({
                            "name": f"ROUTE_{m.group(1).upper()}_{m.group(2)}",
                            "params": params,
                            "start_line": idx,
                            "end_line": idx + 10,
                            "calls": [],
                            "assignments": [],
                            "decorators": [f"router.{m.group(1)}('{m.group(2)}')"]
                        })
                    else:
                        name = m.group(1)
                        params = [p.strip() for p in m.group(2).split(",") if p.strip()]
                        functions.append({
                            "name": name,
                            "params": params,
                            "start_line": idx,
                            "end_line": idx + 10,
                            "calls": [],
                            "assignments": [],
                            "decorators": []
                        })

        # 3. Calls
        call_pattern = r'(\w+(?:\.\w+)?)\s*\(([^)]*)\)'
        for idx, line in enumerate(lines, 1):
            if "function" in line or "const" in line and "=>" in line:
                continue
            for m in re.finditer(call_pattern, line):
                full_call = m.group(1)
                args_str = m.group(2)
                args = [a.strip() for a in args_str.split(",") if a.strip()]
                calls.append({
                    "name": full_call.split(".")[-1],
                    "callee_obj": full_call.split(".")[0] if "." in full_call else "",
                    "full_call": full_call,
                    "args": args,
                    "line": idx
                })

        return {
            "file_path": file_path,
            "language": "javascript",
            "imports": imports,
            "functions": functions,
            "classes": [],
            "calls": calls,
            "error": None
        }
