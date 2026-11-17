from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Finding, Project
from backend.app.schemas.schemas import FindingResponse
from backend.app.remediation.remediation_engine import RemediationEngine

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.post("/{finding_id}/explain")
def explain_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    explanation = (
        f"### Technical Analysis: {finding.title}\n\n"
        f"- **Category:** `{finding.category.upper()}`\n"
        f"- **Severity:** `{finding.severity.upper()}` (Confidence: {int(finding.confidence * 100)}%)\n"
        f"- **Location:** `{finding.file_path}:{finding.start_line}`\n\n"
        f"**Description & Mechanism:**\n{finding.description}\n\n"
        f"**Security & Operational Impact:**\n{finding.impact}\n\n"
        f"**Recommended Action:**\n{finding.recommendation}\n\n"
        f"**Verification Method:**\n{finding.verification}"
    )

    return {
        "finding_id": finding.id,
        "explanation": explanation
    }

@router.post("/{finding_id}/suggest-fix")
def suggest_fix(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    engine = RemediationEngine(project.root_path)
    patch_data = engine.generate_patch({
        "id": finding.id,
        "title": finding.title,
        "category": finding.category,
        "file_path": finding.file_path,
        "snippet": finding.snippet,
        "description": finding.description
    })

    return patch_data
