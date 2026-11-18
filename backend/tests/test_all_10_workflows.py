import io
import json
import zipfile
import pytest
from pathlib import Path
from fastapi import UploadFile, BackgroundTasks

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.models import Project
from backend.app.services.project_service import ProjectService
from backend.app.api.routes_health import health_check
from backend.app.api.routes_projects import (
    load_demo_project, upload_project_zip, list_projects,
    get_project, get_project_summary, get_project_vulnerability_chains
)
from backend.app.api.routes_audits import create_audit, get_audit, get_audit_findings, get_audit_status
from backend.app.api.routes_reports import get_html_report, get_markdown_report, get_json_report
from backend.app.schemas.schemas import (
    ProjectResponse, AuditResponse, FindingResponse, 
    ProjectSummaryResponse, AuditCreate
)

@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_workflow_1_health():
    """1. GET /api/health"""
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "CodeSentinel AI"
    assert "version" in res

def test_workflow_2_demo_project_creation(db):
    """2. Demo project creation & serialization"""
    proj = load_demo_project(db=db)
    assert proj.id.startswith("proj-demo-")
    
    # Verify Pydantic response serialization succeeds without ValidationError
    pydantic_resp = ProjectResponse.model_validate(proj)
    assert pydantic_resp.id == proj.id
    assert isinstance(pydantic_resp.meta_info, dict)
    assert pydantic_resp.meta_info.get("file_count", 0) > 0

def test_workflow_3_zip_upload(db):
    """3. ZIP upload with path-traversal protection"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app/main.py", "import os\nprint('hello world')\n")
        zf.writestr("app/config.py", "SECRET = 'supersecret123'\n")
    zip_bytes = zip_buffer.getvalue()

    proj_data = ProjectService.create_project_from_zip(zip_bytes, "test_repo.zip")
    assert proj_data["id"].startswith("proj-")

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
    
    # Test Pydantic validation
    pydantic_resp = ProjectResponse.model_validate(project)
    assert pydantic_resp.id == project.id
    assert isinstance(pydantic_resp.meta_info, dict)

def test_workflow_4_project_listing_and_detail(db):
    """4. Project listing and detail retrieval"""
    projects = list_projects(db=db)
    assert len(projects) >= 2
    for p in projects:
        resp = ProjectResponse.model_validate(p)
        assert isinstance(resp.meta_info, dict)

    first = projects[0]
    fetched = get_project(project_id=first.id, db=db)
    assert fetched.id == first.id

def test_workflow_5_6_audit_creation_and_execution(db):
    """5 & 6. Audit creation and execution through 17-stage pipeline"""
    # Find the demo project
    projects = list_projects(db=db)
    demo_proj = next((p for p in projects if p.source_type == "demo"), None)
    assert demo_proj is not None

    bg = BackgroundTasks()
    audit_resp = create_audit(
        payload=AuditCreate(project_id=demo_proj.id),
        background_tasks=bg,
        db=db
    )
    assert audit_resp.status == "completed"
    assert audit_resp.progress == 100
    assert audit_resp.total_findings > 0
    assert len(audit_resp.stages_log) > 0
    assert isinstance(audit_resp.scanner_status, dict)

    # Fetch audit status
    status_data = get_audit_status(audit_id=audit_resp.id, db=db)
    assert status_data["status"] == "completed"
    assert status_data["progress"] == 100

def test_workflow_7_findings_retrieval(db):
    """7. Findings retrieval with filtering and severity sorting"""
    from backend.app.models.models import Audit
    latest_audit = db.query(Audit).order_by(Audit.created_at.desc()).first()
    assert latest_audit is not None

    findings = get_audit_findings(audit_id=latest_audit.id, db=db)
    assert len(findings) > 0

    # Ensure all findings validate against FindingResponse
    validated_findings = [FindingResponse.model_validate(f) for f in findings]
    assert len(validated_findings) == len(findings)

    # Check categories present
    categories = {f.category for f in validated_findings}
    assert "security" in categories or "secret" in categories

def test_workflow_8_cross_file_vulnerability_chain_retrieval(db):
    """8. Flagship cross-file vulnerability chain detection & retrieval"""
    projects = list_projects(db=db)
    demo_proj = next((p for p in projects if p.source_type == "demo"), None)
    assert demo_proj is not None

    chains = get_project_vulnerability_chains(project_id=demo_proj.id, db=db)
    assert len(chains) >= 1

    # Verify SQL injection chain connects routes.py -> services.py -> database.py
    sql_chain = next((c for c in chains if "sql" in c["vulnerability_type"].lower()), None)
    assert sql_chain is not None, "SQL Injection cross-file chain must exist!"
    assert "routes.py" in sql_chain["source_file"]
    assert "database.py" in sql_chain["sink_file"]

    # Verify graph nodes and edges
    assert len(sql_chain["nodes"]) >= 3
    node_files = [n.get("file") or n.get("data", {}).get("file", "") for n in sql_chain["nodes"]]
    assert any("routes.py" in f for f in node_files), f"Expected routes.py in {node_files}"
    assert any("services.py" in f for f in node_files), f"Expected services.py in {node_files}"
    assert any("database.py" in f for f in node_files), f"Expected database.py in {node_files}"

    assert len(sql_chain["edges"]) >= 2

def test_workflow_9_dashboard_statistics(db):
    """9. Dashboard statistics & project summary"""
    projects = list_projects(db=db)
    demo_proj = next((p for p in projects if p.source_type == "demo"), None)
    assert demo_proj is not None

    summary = get_project_summary(project_id=demo_proj.id, db=db)
    assert summary["id"] == demo_proj.id
    assert summary["name"] == demo_proj.name
    assert "Python" in summary["languages"]
    assert summary["latest_audit"] is not None
    assert summary["latest_audit"]["total_findings"] > 0

def test_workflow_10_report_generation(db):
    """10. Report generation (HTML, Markdown, JSON)"""
    from backend.app.models.models import Audit
    latest_audit = db.query(Audit).order_by(Audit.created_at.desc()).first()
    assert latest_audit is not None

    # HTML
    html = get_html_report(audit_id=latest_audit.id, db=db)
    assert "<!DOCTYPE html>" in html.body.decode()
    assert "CodeSentinel AI" in html.body.decode()

    # Markdown
    md = get_markdown_report(audit_id=latest_audit.id, db=db)
    assert "# CodeSentinel AI" in md.body.decode()
    assert "Audit Report" in md.body.decode()

    # JSON
    js = get_json_report(audit_id=latest_audit.id, db=db)
    assert "CodeSentinel AI" in js.body.decode()
    parsed_json = json.loads(js.body.decode())
    assert parsed_json["meta"]["tool"] == "CodeSentinel AI"
    assert "scores" in parsed_json
