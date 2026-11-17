from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Project
from backend.app.schemas.schemas import FileContentResponse

router = APIRouter(prefix="/files", tags=["File Viewer"])

@router.get("/content", response_model=FileContentResponse)
def get_file_content(
    project_id: str = Query(...),
    file_path: str = Query(...),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    root = Path(project.root_path).resolve()
    target = (root / file_path).resolve()

    # Prevent path traversal
    if not str(target).startswith(str(root)):
        raise HTTPException(status_code=403, detail="Forbidden file path access.")

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")

    # Detect language for Monaco editor
    ext = target.suffix.lower()
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".json": "json",
        ".html": "html",
        ".css": "css",
        ".md": "markdown",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".sh": "shell",
        ".sql": "sql"
    }
    language = lang_map.get(ext, "plaintext")
    lines = content.splitlines()

    return FileContentResponse(
        file_path=file_path,
        content=content,
        language=language,
        line_count=len(lines)
    )
