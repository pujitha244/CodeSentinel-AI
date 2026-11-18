import os
import shutil
import zipfile
import uuid
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlsplit
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
        shutil.copytree(demo_src, target_dir, dirs_exist_ok=True)

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
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if len(file_content) > max_bytes:
            raise ValueError(f"Upload exceeds the maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB.")

        project_id = f"proj-{uuid.uuid4().hex[:8]}"
        project_root = settings.PROJECTS_DIR.resolve()
        target_dir = project_root / project_id
        target_dir.mkdir(parents=True, exist_ok=False)

        zip_path = settings.UPLOADS_DIR / f"{project_id}.zip"
        try:
            zip_path.write_bytes(file_content)
            total_extracted_size = 0
            max_file_bytes = settings.MAX_FILE_SIZE_KB * 1024
            max_file_count = settings.MAX_FILE_COUNT

            with zipfile.ZipFile(zip_path, "r") as zf:
                members = zf.infolist()
                if len(members) > max_file_count:
                    raise ValueError(f"Archive contains more than {max_file_count} entries.")

                for member in members:
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or "\x00" in member.filename:
                        raise ValueError("Archive contains an invalid absolute path.")

                    target_path = (target_dir / member.filename).resolve()
                    try:
                        target_path.relative_to(target_dir)
                    except ValueError as exc:
                        raise ValueError(
                            f"Archive entry escapes the project directory: {member.filename}"
                        ) from exc

                    total_extracted_size += member.file_size
                    if total_extracted_size > max_bytes:
                        raise ValueError(
                            f"Zip extraction size exceeds the maximum limit of {settings.MAX_UPLOAD_SIZE_MB}MB."
                        )
                    if member.file_size > max_file_bytes and not member.is_dir():
                        raise ValueError(
                            f"Archive entry exceeds the maximum file size of {settings.MAX_FILE_SIZE_KB}KB."
                        )

                    # Ignore symlinks rather than allowing archive-created links.
                    mode = member.external_attr >> 16
                    if (mode & 0o170000) == 0o120000:
                        continue

                    if member.is_dir():
                        target_path.mkdir(parents=True, exist_ok=True)
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, "r") as source, target_path.open("xb") as destination:
                        shutil.copyfileobj(source, destination)

            subdirs = [p for p in target_dir.iterdir() if p.is_dir()]
            actual_root = target_dir
            if len(subdirs) == 1 and not any(p.is_file() for p in target_dir.iterdir()):
                actual_root = subdirs[0]

            meta = ProjectService.inspect_project_structure(str(actual_root))
            safe_filename = Path(filename.replace("\\", "/")).name
            project_name = Path(safe_filename).stem or f"Project-{project_id}"

            return {
                "id": project_id,
                "name": project_name,
                "description": f"Imported archive from {safe_filename}",
                "source_type": "upload",
                "source_url": safe_filename,
                "root_path": str(actual_root),
                "meta_info": meta
            }
        except zipfile.BadZipFile as exc:
            shutil.rmtree(target_dir, ignore_errors=True)
            raise ValueError("The uploaded file is not a valid ZIP archive.") from exc
        except Exception:
            shutil.rmtree(target_dir, ignore_errors=True)
            raise
        finally:
            zip_path.unlink(missing_ok=True)

    @staticmethod
    async def create_project_from_github(repo_url: str, token: Optional[str] = None) -> Dict[str, Any]:
        """
        Downloads a public or private GitHub repository zip archive via GitHub API.
        Does not require a git client or credentials for public repositories.
        """
        parsed_url = urlsplit(repo_url.strip())
        path_parts = parsed_url.path.strip("/").split("/")
        if (
            parsed_url.scheme != "https"
            or parsed_url.hostname != "github.com"
            or len(path_parts) != 2
        ):
            raise ValueError("Invalid GitHub repository URL format. Expected: https://github.com/owner/repo")

        owner = path_parts[0]
        repo = path_parts[1][:-4] if path_parts[1].endswith(".git") else path_parts[1]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+", repo
        ):
            raise ValueError("Invalid GitHub owner or repository name.")

        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        timeout = httpx.Timeout(60.0)
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.get(zip_url, headers=headers)
            if response.status_code in {301, 302, 303, 307, 308}:
                download_url = response.headers.get("location", "")
                download_host = urlsplit(download_url).hostname
                if (
                    urlsplit(download_url).scheme != "https"
                    or download_host != "codeload.github.com"
                ):
                    raise ValueError("GitHub returned an unsupported archive download location.")
            elif response.status_code == 200:
                download_url = zip_url
            else:
                raise ValueError(f"GitHub repository download failed (HTTP {response.status_code}).")

            download_headers = {} if download_url != zip_url else headers
            async with client.stream("GET", download_url, headers=download_headers) as download:
                if download.status_code != 200:
                    raise ValueError(
                        f"GitHub archive download failed (HTTP {download.status_code})."
                    )

                chunks = []
                downloaded = 0
                async for chunk in download.aiter_bytes():
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise ValueError(
                            f"GitHub archive exceeds the maximum download size of {settings.MAX_UPLOAD_SIZE_MB}MB."
                        )
                    chunks.append(chunk)

        zip_bytes = b"".join(chunks)

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
