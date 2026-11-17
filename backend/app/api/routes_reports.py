import json
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Audit, Project, Finding, VulnerabilityChain
from backend.app.reports.report_generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["Reports"])

def _gather_audit_data(audit_id: str, db: Session):
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    project = db.query(Project).filter(Project.id == audit.project_id).first()
    findings = db.query(Finding).filter(Finding.audit_id == audit_id).all()
    chains = db.query(VulnerabilityChain).filter(VulnerabilityChain.audit_id == audit_id).all()

    audit_dict = {
        "id": audit.id,
        "security_score": audit.security_score,
        "quality_score": audit.quality_score,
        "completeness_score": audit.completeness_score,
        "engineering_health_score": audit.engineering_health_score,
        "slop_score": audit.slop_score,
        "total_findings": audit.total_findings,
        "critical_count": audit.critical_count,
        "high_count": audit.high_count,
        "medium_count": audit.medium_count,
        "low_count": audit.low_count
    }

    project_dict = {
        "name": project.name if project else "Project",
        "id": project.id if project else ""
    }

    findings_list = [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "end_line": f.end_line,
            "snippet": f.snippet,
            "description": f.description,
            "impact": f.impact,
            "recommendation": f.recommendation,
            "detection_method": f.detection_method,
            "status": f.status
        }
        for f in findings
    ]

    chains_list = [
        {
            "id": c.id,
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
            "nodes": json.loads(c.nodes_data or "[]"),
            "edges": json.loads(c.edges_data or "[]")
        }
        for c in chains
    ]

    return audit_dict, project_dict, findings_list, chains_list

@router.get("/{audit_id}/html", response_class=HTMLResponse)
def get_html_report(audit_id: str, db: Session = Depends(get_db)):
    a, p, f, c = _gather_audit_data(audit_id, db)
    html_content = ReportGenerator.generate_html(a, p, f, c)
    return HTMLResponse(content=html_content)

@router.get("/{audit_id}/markdown", response_class=PlainTextResponse)
def get_markdown_report(audit_id: str, db: Session = Depends(get_db)):
    a, p, f, c = _gather_audit_data(audit_id, db)
    md_content = ReportGenerator.generate_markdown(a, p, f, c)
    return PlainTextResponse(content=md_content)

@router.get("/{audit_id}/json")
def get_json_report(audit_id: str, db: Session = Depends(get_db)):
    a, p, f, c = _gather_audit_data(audit_id, db)
    json_str = ReportGenerator.generate_json(a, p, f, c)
    return Response(content=json_str, media_type="application/json")
