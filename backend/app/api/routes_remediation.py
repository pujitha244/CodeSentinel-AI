import json
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Finding, Project, Audit, RemediationPatch
from backend.app.remediation.remediation_engine import RemediationEngine
from backend.app.scanners.security_scanner import SecurityScanner
from backend.app.scanners.secret_scanner import SecretScanner

router = APIRouter(prefix="/remediation", tags=["Remediation Lab"])

@router.post("/{finding_id}/preview")
def preview_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    engine = RemediationEngine(project.root_path)
    try:
        patch = engine.generate_patch({
            "id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "file_path": finding.file_path,
            "snippet": finding.snippet,
            "description": finding.description
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Persist patch record
    db_patch = RemediationPatch(
        id=patch["patch_id"],
        finding_id=finding.id,
        audit_id=finding.audit_id,
        file_path=finding.file_path,
        original_snippet=patch["original_snippet"],
        replacement_snippet=patch["replacement_snippet"],
        unified_diff=patch["unified_diff"],
        explanation=patch["explanation"],
        status="previewed"
    )
    db.add(db_patch)
    db.commit()

    return patch

@router.post("/{finding_id}/apply")
def apply_remediation(
    finding_id: str, 
    payload: dict = Body(...), 
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    patched_code = payload.get("patched_code")
    patch_id = payload.get("patch_id")
    if not patched_code:
        raise HTTPException(status_code=400, detail="Missing patched_code parameter.")

    engine = RemediationEngine(project.root_path)
    success = engine.apply_patch(finding.file_path, patched_code)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to apply patch to target file.")

    finding.status = "fixed"
    if patch_id:
        patch = db.query(RemediationPatch).filter(RemediationPatch.id == patch_id).first()
        if patch:
            patch.status = "applied"

    db.commit()

    return {
        "status": "applied",
        "finding_id": finding.id,
        "file_path": finding.file_path,
        "message": f"Patch successfully applied to {finding.file_path}. Backup retained for safe rollback."
    }

@router.post("/{finding_id}/verify")
def verify_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Re-scan the specific file using security scanner
    sec_scanner = SecurityScanner()
    new_findings = sec_scanner.scan(project.root_path, [finding.file_path])
    
    # Also check secret scanner if it was a secret finding
    if finding.category == "secret":
        secr_scanner = SecretScanner()
        new_findings += secr_scanner.scan(project.root_path, [finding.file_path])

    # Check if original finding still triggers
    is_still_vulnerable = any(
        f["title"] == finding.title and abs(f["start_line"] - finding.start_line) <= 5
        for f in new_findings
    )

    if not is_still_vulnerable:
        finding.status = "verified"
        db.commit()
        return {
            "verified": True,
            "status": "verified",
            "message": "Verification passed! Targeted static analysis confirms the vulnerability is neutralized."
        }
    else:
        return {
            "verified": False,
            "status": "still_vulnerable",
            "message": "Verification failed: security scanner still detected the issue."
        }

@router.post("/{finding_id}/rollback")
def rollback_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    engine = RemediationEngine(project.root_path)
    rolled_back = engine.rollback_patch(finding.file_path)
    if not rolled_back:
        raise HTTPException(status_code=400, detail="No backup copy found to rollback.")

    finding.status = "open"
    db.commit()

    return {
        "status": "rolled_back",
        "finding_id": finding.id,
        "message": f"Successfully rolled back {finding.file_path} to original state."
    }
