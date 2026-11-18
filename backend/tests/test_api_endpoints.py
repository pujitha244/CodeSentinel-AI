import pytest
from backend.app.core.database import SessionLocal, Base, engine
from backend.app.api.routes_health import health_check
from backend.app.api.routes_projects import load_demo_project, get_project_architecture_graph, get_project_vulnerability_chains
from backend.app.api.routes_audits import create_audit, get_audit, get_audit_findings
from backend.app.api.routes_remediation import (
    apply_remediation,
    preview_remediation,
    rollback_remediation,
    verify_remediation,
)
from backend.app.api.routes_reports import get_html_report, get_markdown_report, get_json_report
from backend.app.schemas.schemas import AuditCreate

@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_health_route():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "CodeSentinel AI"

def test_routes_complete_lifecycle(db):
    # 1. Load Demo Project
    proj = load_demo_project(db=db)
    assert proj.id.startswith("proj-demo-")
    project_id = proj.id

    # 2. Get Architecture Graph
    graph = get_project_architecture_graph(project_id=project_id, db=db)
    assert "nodes" in graph
    assert len(graph["nodes"]) > 0

    # 3. Create Audit
    from fastapi import BackgroundTasks
    bg = BackgroundTasks()
    audit_resp = create_audit(payload=AuditCreate(project_id=project_id), background_tasks=bg, db=db)
    assert audit_resp.status == "completed"
    audit_id = audit_resp.id

    # 4. Get Audit Status & Details
    audit_fetched = get_audit(audit_id=audit_id, db=db)
    assert audit_fetched.id == audit_id
    assert audit_fetched.total_findings > 0

    # 5. Get Findings
    findings = get_audit_findings(audit_id=audit_id, db=db)
    assert len(findings) > 0

    # 6. Get Chains
    chains = get_project_vulnerability_chains(project_id=project_id, db=db)
    assert len(chains) >= 1

    # 7. Preview Remediation
    sql_finding = next(f for f in findings if "sql" in f.title.lower())
    patch = preview_remediation(finding_id=sql_finding.id, db=db)
    assert patch["unified_diff"] != ""

    # 8. Reports
    html_resp = get_html_report(audit_id=audit_id, db=db)
    assert "<!DOCTYPE html>" in html_resp.body.decode()

    md_resp = get_markdown_report(audit_id=audit_id, db=db)
    assert "# CodeSentinel AI" in md_resp.body.decode()

    json_resp = get_json_report(audit_id=audit_id, db=db)
    assert "CodeSentinel AI" in json_resp.body.decode()

    sql_patch = preview_remediation(finding_id=sql_finding.id, db=db)
    assert verify_remediation(finding_id=sql_finding.id, db=db)["verified"] is False
    applied = apply_remediation(
        finding_id=sql_finding.id,
        payload={
            "patch_id": sql_patch["patch_id"],
            "patched_code": sql_patch["patched_code"],
        },
        db=db,
    )
    assert applied["status"] == "applied"
    assert verify_remediation(finding_id=sql_finding.id, db=db)["verified"] is True
    assert rollback_remediation(finding_id=sql_finding.id, db=db)["status"] == "rolled_back"
    assert verify_remediation(finding_id=sql_finding.id, db=db)["verified"] is False
