import json
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.models import Finding, Project, Audit, RemediationPatch, VulnerabilityChain
from backend.app.analyzers.ast_engine import CodeParser
from backend.app.analyzers.call_graph_builder import CallGraphBuilder
from backend.app.analyzers.taint_engine import TaintEngine
from backend.app.remediation.remediation_engine import RemediationEngine
from backend.app.scanners.security_scanner import SecurityScanner
from backend.app.scanners.secret_scanner import SecretScanner

router = APIRouter(prefix="/remediation", tags=["Remediation Lab"])

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
            detail="This legacy finding ID is ambiguous across audits; select a finding from the latest audit."
        )
    return matches[0]


def _chain_still_exists(project: Project, expected_chain: VulnerabilityChain) -> bool:
    root = Path(project.root_path).resolve()
    try:
        metadata = json.loads(project.meta_info or "{}")
    except (TypeError, json.JSONDecodeError):
        metadata = {}

    parsed_files = {}
    for item in metadata.get("files", []):
        relative_path = item.get("path", "")
        file_path = (root / relative_path).resolve()
        try:
            file_path.relative_to(root)
        except ValueError:
            continue
        if not file_path.is_file() or file_path.is_symlink():
            continue

        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if relative_path.endswith(".py"):
            parsed_files[relative_path] = CodeParser.parse_python(relative_path, code)
        elif relative_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            parsed_files[relative_path] = CodeParser.parse_javascript(relative_path, code)

    call_graph = CallGraphBuilder(str(root), parsed_files).build()
    chains = TaintEngine(str(root), parsed_files, call_graph).analyze()
    return any(
        chain["source_file"] == expected_chain.source_file
        and chain["source_line"] == expected_chain.source_line
        and chain["sink_file"] == expected_chain.sink_file
        and chain["vulnerability_type"] == expected_chain.vulnerability_type
        for chain in chains
    )


@router.post("/{finding_id}/preview")
def preview_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id)

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
    finding = _get_finding(db, finding_id)

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    patched_code = payload.get("patched_code")
    patch_id = payload.get("patch_id")
    if not patched_code or not patch_id:
        raise HTTPException(status_code=400, detail="Missing patch_id or patched_code parameter.")

    engine = RemediationEngine(project.root_path)
    patch_record = db.query(RemediationPatch).filter(
        RemediationPatch.id == patch_id,
        RemediationPatch.finding_id == finding.id,
        RemediationPatch.audit_id == finding.audit_id,
        RemediationPatch.file_path == finding.file_path
    ).first()
    if not patch_record or patch_record.status != "previewed":
        raise HTTPException(status_code=409, detail="Patch preview is missing, stale, or already used.")

    try:
        current_preview = engine.generate_patch({
            "id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "file_path": finding.file_path,
            "snippet": finding.snippet,
            "description": finding.description
        })
        if (
            not current_preview["has_changes"]
            or current_preview["patched_code"] != patched_code
            or current_preview["unified_diff"] != patch_record.unified_diff
        ):
            raise HTTPException(
                status_code=409,
                detail="Source or patch changed after preview; generate and review a new patch."
            )
        success = engine.apply_patch(
            finding.file_path,
            patched_code,
            expected_code=current_preview["original_code"]
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to apply patch to target file.")

    finding.status = "fixed"
    patch_record.status = "applied"

    db.commit()

    return {
        "status": "applied",
        "finding_id": finding.id,
        "file_path": finding.file_path,
        "message": f"Patch successfully applied to {finding.file_path}. Backup retained for safe rollback."
    }

@router.post("/{finding_id}/verify")
def verify_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id)

    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if finding.chain_id:
        expected_chain = db.query(VulnerabilityChain).filter(
            VulnerabilityChain.id == finding.chain_id,
            VulnerabilityChain.audit_id == finding.audit_id
        ).first()
        if expected_chain is None:
            raise HTTPException(
                status_code=409,
                detail="The original vulnerability chain is unavailable; rerun the audit before verifying."
            )
        is_still_vulnerable = _chain_still_exists(project, expected_chain)
    else:
        scanner_findings = SecurityScanner().scan(project.root_path, [finding.file_path])
        if finding.category == "secret":
            scanner_findings += SecretScanner().scan(project.root_path, [finding.file_path])
        is_still_vulnerable = any(
            result["title"] == finding.title
            and result["file_path"] == finding.file_path
            for result in scanner_findings
        )

    if not is_still_vulnerable:
        finding.status = "verified"
        db.commit()
        return {
            "verified": True,
            "status": "verified",
            "message": "Verification passed: the targeted static analyzer did not reproduce the finding. This does not prove the application is free of vulnerabilities."
        }
    else:
        return {
            "verified": False,
            "status": "still_vulnerable",
            "message": "Verification failed: targeted static analysis still reproduces the vulnerability."
        }

@router.post("/{finding_id}/rollback")
def rollback_remediation(finding_id: str, db: Session = Depends(get_db)):
    finding = _get_finding(db, finding_id)

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
