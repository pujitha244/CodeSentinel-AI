import json
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.models.models import Project, Audit, VulnerabilityChain
from backend.app.schemas.schemas import ProjectResponse, ProjectSummaryResponse, ArchitectureGraphResponse
from backend.app.services.project_service import ProjectService
from backend.app.analyzers.ast_engine import CodeParser
from backend.app.analyzers.call_graph_builder import CallGraphBuilder

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.post("/demo", response_model=ProjectResponse)
def load_demo_project(db: Session = Depends(get_db)):
    """
    Loads the mandatory flagship multi-file vulnerable Python demonstration project.
    """
    proj_data = ProjectService.create_project_from_demo()
    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type=proj_data["source_type"],
        source_url=proj_data["source_url"],
        root_path=proj_data["root_path"],
        meta_info=json.dumps(proj_data["meta_info"])
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project

@router.post("/upload", response_model=ProjectResponse)
async def upload_project_zip(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Uploads and extracts a project ZIP archive.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are supported.")

    content = await file.read(settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024 + 1)
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds the maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB."
        )
    try:
        proj_data = ProjectService.create_project_from_zip(content, file.filename)
    except (ValueError, OSError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type=proj_data["source_type"],
        source_url=proj_data["source_url"],
        root_path=proj_data["root_path"],
        meta_info=json.dumps(proj_data["meta_info"])
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project

@router.post("/github", response_model=ProjectResponse)
async def ingest_github_repo(
    repo_url: str = Form(...),
    token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingests a public or private GitHub repository without requiring local git installation.
    """
    try:
        proj_data = await ProjectService.create_project_from_github(repo_url, token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type="github",
        source_url=repo_url,
        root_path=proj_data["root_path"],
        meta_info=json.dumps(proj_data["meta_info"])
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project

@router.get("", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.created_at.desc()).all()

@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.get("/{project_id}/summary", response_model=ProjectSummaryResponse)
def get_project_summary(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    meta = project.get_meta()
    latest_audit = (
        db.query(Audit)
        .filter(Audit.project_id == project_id)
        .order_by(Audit.created_at.desc())
        .first()
    )

    audit_summary = None
    if latest_audit:
        audit_summary = {
            "id": latest_audit.id,
            "status": latest_audit.status,
            "security_score": latest_audit.security_score,
            "engineering_health_score": latest_audit.engineering_health_score,
            "total_findings": latest_audit.total_findings,
            "critical_count": latest_audit.critical_count
        }

    return {
        "id": project.id,
        "name": project.name,
        "languages": meta.get("languages", ["Unknown"]),
        "frameworks": meta.get("frameworks", []),
        "file_count": meta.get("file_count", 0),
        "line_count": meta.get("line_count", 0),
        "entry_points": meta.get("entry_points", []),
        "latest_audit": audit_summary
    }

@router.get("/{project_id}/graph", response_model=ArchitectureGraphResponse)
def get_project_architecture_graph(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    root_path = Path(project.root_path).resolve()
    meta = project.get_meta()
    all_files = [f["path"] for f in meta.get("files", [])]

    parsed_files = {}
    for rel_file in all_files:
        file_abs = root_path / rel_file
        if not file_abs.is_file():
            continue
        try:
            code = file_abs.read_text(encoding="utf-8", errors="ignore")
            if rel_file.endswith(".py"):
                parsed_files[rel_file] = CodeParser.parse_python(rel_file, code)
            elif rel_file.endswith((".js", ".ts", ".jsx", ".tsx")):
                parsed_files[rel_file] = CodeParser.parse_javascript(rel_file, code)
        except Exception:
            continue

    builder = CallGraphBuilder(str(root_path), parsed_files)
    builder.build()
    return builder.get_architecture_graph()

@router.get("/{project_id}/vulnerability-chains")
def get_project_vulnerability_chains(project_id: str, db: Session = Depends(get_db)):
    if not db.query(Project.id).filter(Project.id == project_id).first():
        raise HTTPException(status_code=404, detail="Project not found")

    latest_audit = (
        db.query(Audit)
        .filter(Audit.project_id == project_id)
        .order_by(Audit.created_at.desc())
        .first()
    )
    if latest_audit is None:
        return []

    chains = (
        db.query(VulnerabilityChain)
        .filter(VulnerabilityChain.audit_id == latest_audit.id)
        .all()
    )
    result = []
    for c in chains:
        result.append({
            "id": c.id,
            "audit_id": c.audit_id,
            "project_id": c.project_id,
            "title": c.title,
            "vulnerability_type": c.vulnerability_type,
            "severity": c.severity,
            "confidence": c.confidence,
            "source_file": c.source_file,
            "source_line": c.source_line,
            "sink_file": c.sink_file,
            "sink_line": c.sink_line,
            "description": c.description,
            "remediation_summary": c.remediation_summary,
            "verified": c.verified,
            "nodes": json.loads(c.nodes_data or "[]"),
            "edges": json.loads(c.edges_data or "[]"),
            "created_at": c.created_at
        })
    return result
