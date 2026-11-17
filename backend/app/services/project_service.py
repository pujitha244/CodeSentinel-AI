import os
import shutil
import zipfile
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx
from backend.app.core.config import settings

class ProjectService:
    @staticmethod
    def create_project_from_demo() -> Dict[str, Any]:
        """
        Loads the pre-configured vulnerable Python demonstration repository.
        """
        demo_src = settings.SAMPLE_PROJECTS_DIR / "vulnerable-python"
        if not demo_src.exists():
            raise FileNotFoundError(f"Demo project not found at {demo_src}")

        project_id = f"proj-demo-{uuid.uuid4().hex[:6]}"
        target_dir = settings.PROJECTS_DIR / project_id
        shutil.copytree(demo_src, target_dir)

        meta = ProjectService.inspect_project_structure(str(target_dir))

        return {
            "id": project_id,
            "name": "Vulnerable Multi-Tier Python Demo",
            "description": "Intentionally vulnerable multi-tier Python application with cross-file SQL injection propagation, hardcoded secrets, code slop, and logic gaps.",
            "source_type": "demo",
            "source_url": "built-in://sample-projects/vulnerable-python",
            "root_path": str(target_dir),
            "meta_info": meta
        }

    @staticmethod
    def create_project_from_zip(file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        Securely extracts an uploaded zip archive with path traversal and size protections.
        """
        project_id = f"proj-{uuid.uuid4().hex[:8]}"
        target_dir = settings.PROJECTS_DIR / project_id
        target_dir.mkdir(parents=True, exist_ok=True)

        zip_path = settings.UPLOADS_DIR / f"{project_id}.zip"
        zip_path.write_bytes(file_content)

        # Secure extraction
        total_extracted_size = 0
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                # Guard against zip-slip path traversal
                target_path = (target_dir / member.filename).resolve()
                if not str(target_path).startswith(str(target_dir.resolve())):
                    raise ValueError(f"Malicious zip entry attempting path traversal: {member.filename}")

                # Guard against zip bombs
                total_extracted_size += member.file_size
                if total_extracted_size > max_bytes:
                    raise ValueError(f"Zip extraction size exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_MB}MB.")

                # Skip suspicious symlinks
                if (member.external_attr >> 16) & 0o120000 == 0o120000:
                    continue

                zf.extract(member, target_dir)

        # If zip extracted into a single wrapper folder, adjust root_path
        subdirs = [p for p in target_dir.iterdir() if p.is_dir()]
        actual_root = target_dir
        if len(subdirs) == 1 and not any(p.is_file() for p in target_dir.iterdir()):
            actual_root = subdirs[0]

        meta = ProjectService.inspect_project_structure(str(actual_root))
        project_name = Path(filename).stem or f"Project-{project_id}"

        return {
            "id": project_id,
            "name": project_name,
            "description": f"Imported archive from {filename}",
            "source_type": "upload",
            "source_url": filename,
            "root_path": str(actual_root),
            "meta_info": meta
        }

    @staticmethod
    async def create_project_from_github(repo_url: str, token: Optional[str] = None) -> Dict[str, Any]:
        """
        Downloads a public or private GitHub repository zip archive via GitHub API.
        Does not require a git client or credentials for public repositories.
        """
        clean_url = repo_url.strip().rstrip("/")
        # Extract owner/repo
        parts = clean_url.split("github.com/")[-1].split("/")
        if len(parts) < 2:
            raise ValueError("Invalid GitHub repository URL format. Expected: https://github.com/owner/repo")

        owner = parts[0]
        repo = parts[1].replace(".git", "")

        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            resp = await client.get(zip_url, headers=headers)
            if resp.status_code != 200:
                raise ValueError(f"Failed to fetch GitHub repository ({resp.status_code}): {resp.text[:120]}")
            zip_bytes = resp.content

        return ProjectService.create_project_from_zip(zip_bytes, f"{owner}_{repo}.zip")

    @staticmethod
    def inspect_project_structure(root_dir: str) -> Dict[str, Any]:
        """
        Indexes files, identifies languages, frameworks, dependencies, and entry points.
        """
        root = Path(root_dir).resolve()
        indexed_files = []
        languages = set()
        frameworks = set()
        total_lines = 0

        ignore_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv", "env", "dist", "build", ".idea", ".vscode"}

        for p in root.rglob("*"):
            if any(ignored in p.parts for ignored in ignore_dirs):
                continue
            if p.is_file():
                ext = p.suffix.lower()
                rel_path = str(p.relative_to(root)).replace("\\", "/")
                
                # Language detection
                if ext == ".py":
                    languages.add("Python")
                elif ext in [".js", ".jsx"]:
                    languages.add("JavaScript")
                elif ext in [".ts", ".tsx"]:
                    languages.add("TypeScript")
                elif ext == ".java":
                    languages.add("Java")
                elif ext in [".c", ".h"]:
                    languages.add("C")
                elif ext in [".cpp", ".hpp"]:
                    languages.add("C++")
                elif ext == ".go":
                    languages.add("Go")

                try:
                    line_count = len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
                    total_lines += line_count
                except Exception:
                    line_count = 0

                indexed_files.append({
                    "path": rel_path,
                    "extension": ext,
                    "size_bytes": p.stat().st_size,
                    "lines": line_count
                })

        # Framework detection
        file_paths = [f["path"].lower() for f in indexed_files]
        if any("fastapi" in f or "routes.py" in f for f in file_paths):
            frameworks.add("FastAPI")
        if any("manage.py" in f or "settings.py" in f for f in file_paths):
            frameworks.add("Django")
        if any("app.py" in f or "wsgi.py" in f for f in file_paths):
            frameworks.add("Flask")
        if any("package.json" in f for f in file_paths):
            frameworks.add("Node.js")
        if any("express" in f for f in file_paths):
            frameworks.add("Express")

        # Entry points
        entry_points = [
            f["path"] for f in indexed_files 
            if f["path"].endswith(("main.py", "app.py", "index.js", "server.js", "manage.py", "routes.py"))
        ]

        return {
            "file_count": len(indexed_files),
            "line_count": total_lines,
            "languages": list(languages) or ["Generic"],
            "frameworks": list(frameworks),
            "entry_points": entry_points,
            "files": indexed_files
        }
