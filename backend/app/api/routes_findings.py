from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Finding, Project
from backend.app.schemas.schemas import FindingResponse
from backend.app.remediation.remediation_engine import RemediationEngine

router = APIRouter(prefix="/findings", tags=["Findings"])

def _get_finding(db: Session, finding_id: str) -> Finding:
    matches = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .order_by(Finding.created_at.desc())
        .limit(2)
        .all()
    )
    if not matches:
        raise HTTPException(status_code=404, detail="Finding not found")
    if len(matches) > 1:
        raise HTTPException(
            status_code=409,
            detail="This legacy finding ID is ambiguous across audits; reload the latest audit."
        )
    return matches[0]


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    return _get_finding(db, finding_id)

@router.post("/{finding_id}/explain")
def explain_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id)

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
    finding = _get_finding(db, finding_id)

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
