import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Project, Audit, Finding, VulnerabilityChain
from backend.app.schemas.schemas import AssistantChatRequest, AssistantChatResponse
from backend.app.agents.ai_service import AIService

router = APIRouter(prefix="/assistant", tags=["AI Assistant"])

@router.post("/chat", response_model=AssistantChatResponse)
async def chat_with_assistant(
    request: AssistantChatRequest,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == request.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Fetch audit findings & chains for grounding
    audit_query = db.query(Audit).filter(Audit.project_id == project.id)
    if request.audit_id:
        audit = audit_query.filter(Audit.id == request.audit_id).first()
    else:
        audit = audit_query.order_by(Audit.created_at.desc()).first()

    findings_context = []
    chains_context = []

    if audit:
        findings = db.query(Finding).filter(Finding.audit_id == audit.id).all()
        findings_context = [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "description": f.description,
                "snippet": f.snippet
            }
            for f in findings
        ]

        chains = db.query(VulnerabilityChain).filter(VulnerabilityChain.audit_id == audit.id).all()
        chains_context = [
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
                "remediation_summary": c.remediation_summary
            }
            for c in chains
        ]

    user_query = request.messages[-1].content if request.messages else "Summarize the security audit findings."

    ai_service = AIService()
    result = await ai_service.chat(
        user_message=user_query,
        project_context={"id": project.id, "name": project.name, "meta_info": project.get_meta()},
        findings_context=findings_context,
        chains_context=chains_context
    )

    return AssistantChatResponse(
        reply=result["reply"],
        evidence_references=result.get("evidence_references", [])
    )
