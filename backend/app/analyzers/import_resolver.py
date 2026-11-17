import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class ImportResolver:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()

    def resolve_python_import(self, current_file: str, module_name: str, item_name: str = "") -> Optional[str]:
        """
        Resolves a python import like 'backend.services' or '.services' relative to current_file or project_root.
        Returns the resolved file path relative to project_root, or None if external.
        """
        curr_path = (self.project_root / current_file).resolve()
        curr_dir = curr_path.parent

        # 1. Check relative import (e.g. .services)
        if module_name.startswith("."):
            level = len(module_name) - len(module_name.lstrip("."))
            target_dir = curr_dir
            for _ in range(level - 1):
                target_dir = target_dir.parent
            remainder = module_name.lstrip(".")
            candidate = target_dir / (remainder.replace(".", "/") + ".py")
            if candidate.exists():
                return str(candidate.relative_to(self.project_root)).replace("\\", "/")
            init_candidate = target_dir / remainder.replace(".", "/") / "__init__.py"
            if init_candidate.exists():
                return str(init_candidate.relative_to(self.project_root)).replace("\\", "/")

        # 2. Check absolute from project root (e.g. backend.services)
        parts = module_name.split(".")
        cand_path = self.project_root / "/".join(parts)
        py_cand = cand_path.with_suffix(".py")
        if py_cand.exists():
            return str(py_cand.relative_to(self.project_root)).replace("\\", "/")

        init_cand = cand_path / "__init__.py"
        if init_cand.exists():
            return str(init_cand.relative_to(self.project_root)).replace("\\", "/")

        # Check if item_name might be a file inside module_name (e.g., from backend import services)
        if item_name:
            cand_item = (self.project_root / "/".join(parts) / f"{item_name}.py")
            if cand_item.exists():
                return str(cand_item.relative_to(self.project_root)).replace("\\", "/")

        # Check relative to current directory
        rel_cand = curr_dir / "/".join(parts)
        if rel_cand.with_suffix(".py").exists():
            return str(rel_cand.with_suffix(".py").relative_to(self.project_root)).replace("\\", "/")

        return None

    def resolve_js_import(self, current_file: str, import_path: str) -> Optional[str]:
        """
        Resolves a JS/TS require or import statement (e.g. '../controllers/fileController').
        """
        if not import_path.startswith("."):
            return None  # Node module or absolute alias

        curr_path = (self.project_root / current_file).resolve()
        curr_dir = curr_path.parent
        target = (curr_dir / import_path).resolve()

        extensions = [".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts"]
        for ext in [""] + extensions:
            cand = Path(str(target) + ext)
            if cand.is_file():
                try:
                    return str(cand.relative_to(self.project_root)).replace("\\", "/")
                except ValueError:
                    return None
        return None
