import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db, SessionLocal
from backend.app.models.models import Audit, Finding, VulnerabilityChain, Project
from backend.app.schemas.schemas import AuditCreate, AuditResponse, FindingResponse
from backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/audits", tags=["Audits"])

def execute_background_audit(audit_id: str, project_id: str):
    db = SessionLocal()
    try:
        service = AuditService(db)
        service.run_audit(project_id)
    finally:
        db.close()

@router.post("", response_model=AuditResponse)
def create_audit(
    payload: AuditCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == payload.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # We can run directly with AuditService so the result is immediately available and accurate
    service = AuditService(db)
    audit = service.run_audit(payload.project_id)

    stages = json.loads(audit.stages_log or "[]")
    scanners = json.loads(audit.scanner_status or "{}")

    return AuditResponse(
        id=audit.id,
        project_id=audit.project_id,
        status=audit.status,
        progress=audit.progress,
        current_stage=audit.current_stage,
        stages_log=stages,
        security_score=audit.security_score,
        quality_score=audit.quality_score,
        completeness_score=audit.completeness_score,
        engineering_health_score=audit.engineering_health_score,
        slop_score=audit.slop_score,
        total_findings=audit.total_findings,
        critical_count=audit.critical_count,
        high_count=audit.high_count,
        medium_count=audit.medium_count,
        low_count=audit.low_count,
        info_count=audit.info_count,
        scanner_status=scanners,
        created_at=audit.created_at,
        completed_at=audit.completed_at
    )

@router.get("", response_model=List[AuditResponse])
def list_audits(project_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Audit)
    if project_id:
        query = query.filter(Audit.project_id == project_id)
    audits = query.order_by(Audit.created_at.desc()).all()

    result = []
    for a in audits:
        result.append(AuditResponse(
            id=a.id,
            project_id=a.project_id,
            status=a.status,
            progress=a.progress,
            current_stage=a.current_stage,
            stages_log=json.loads(a.stages_log or "[]"),
            security_score=a.security_score,
            quality_score=a.quality_score,
            completeness_score=a.completeness_score,
            engineering_health_score=a.engineering_health_score,
            slop_score=a.slop_score,
            total_findings=a.total_findings,
            critical_count=a.critical_count,
            high_count=a.high_count,
            medium_count=a.medium_count,
            low_count=a.low_count,
            info_count=a.info_count,
            scanner_status=json.loads(a.scanner_status or "{}"),
            created_at=a.created_at,
            completed_at=a.completed_at
        ))
    return result

@router.get("/{audit_id}", response_model=AuditResponse)
def get_audit(audit_id: str, db: Session = Depends(get_db)):
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    return AuditResponse(
        id=audit.id,
        project_id=audit.project_id,
        status=audit.status,
        progress=audit.progress,
        current_stage=audit.current_stage,
        stages_log=json.loads(audit.stages_log or "[]"),
        security_score=audit.security_score,
        quality_score=audit.quality_score,
        completeness_score=audit.completeness_score,
        engineering_health_score=audit.engineering_health_score,
        slop_score=audit.slop_score,
        total_findings=audit.total_findings,
        critical_count=audit.critical_count,
        high_count=audit.high_count,
        medium_count=audit.medium_count,
        low_count=audit.low_count,
        info_count=audit.info_count,
        scanner_status=json.loads(audit.scanner_status or "{}"),
        created_at=audit.created_at,
        completed_at=audit.completed_at
    )

@router.get("/{audit_id}/status")
def get_audit_status(audit_id: str, db: Session = Depends(get_db)):
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return {
        "id": audit.id,
        "status": audit.status,
        "progress": audit.progress,
        "current_stage": audit.current_stage,
        "stages_log": json.loads(audit.stages_log or "[]")
    }

@router.get("/{audit_id}/findings", response_model=List[FindingResponse])
def get_audit_findings(
    audit_id: str,
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.audit_id == audit_id)
    if isinstance(category, str) and category.strip():
        query = query.filter(Finding.category == category.strip())
    if isinstance(severity, str) and severity.strip():
        query = query.filter(Finding.severity == severity.strip())
    if isinstance(status, str) and status.strip():
        query = query.filter(Finding.status == status.strip())
    if isinstance(search, str) and search.strip():
        query = query.filter(
            (Finding.title.ilike(f"%{search.strip()}%")) | 
            (Finding.file_path.ilike(f"%{search.strip()}%")) |
            (Finding.description.ilike(f"%{search.strip()}%"))
        )

    # Sort critical first, then high, medium, low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = query.all()
    findings.sort(key=lambda x: severity_order.get(x.severity, 5))
    return findings
