import pytest
from pathlib import Path
from backend.app.core.database import SessionLocal, Base, engine
from backend.app.services.project_service import ProjectService
from backend.app.services.audit_service import AuditService
from backend.app.models.models import Project, Audit, Finding, VulnerabilityChain
from backend.app.remediation.remediation_engine import RemediationEngine
from backend.app.reports.report_generator import ReportGenerator

@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()

def test_demo_project_creation(db_session):
    proj_data = ProjectService.create_project_from_demo()
    assert proj_data["id"].startswith("proj-demo-")
    assert "Vulnerable" in proj_data["name"]
    assert Path(proj_data["root_path"]).exists()

    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type=proj_data["source_type"],
        source_url=proj_data["source_url"],
        root_path=proj_data["root_path"],
        meta_info=str(proj_data["meta_info"])
    )
    db_session.add(project)
    db_session.commit()

    saved_proj = db_session.query(Project).filter(Project.id == project.id).first()
    assert saved_proj is not None

def test_audit_execution_and_flagship_cross_file_chain(db_session):
    # Retrieve demo project
    project = db_session.query(Project).filter(Project.source_type == "demo").first()
    assert project is not None

    service = AuditService(db_session)
    audit = service.run_audit(project.id)

    assert audit.status == "completed"
    assert audit.progress == 100
    assert audit.total_findings > 0

    # Verify Flagship Feature: Cross-File Vulnerability Chain was discovered
    chains = db_session.query(VulnerabilityChain).filter(VulnerabilityChain.audit_id == audit.id).all()
    assert len(chains) >= 1

    sql_chain = next((c for c in chains if "sql" in c.vulnerability_type.lower()), None)
    assert sql_chain is not None, "Cross-file SQL injection chain must be detected!"
    assert "routes.py" in sql_chain.source_file, f"Expected source in routes.py, got {sql_chain.source_file}"
    assert "database.py" in sql_chain.sink_file, f"Expected sink in database.py, got {sql_chain.sink_file}"
    assert sql_chain.confidence >= 0.85

    # Verify correlated parent finding
    findings = db_session.query(Finding).filter(Finding.audit_id == audit.id).all()
    chain_finding = next((f for f in findings if f.chain_id == sql_chain.id), None)
    assert chain_finding is not None
    assert chain_finding.severity == "critical"

    # Verify secrets detection
    secret_findings = [f for f in findings if f.category == "secret"]
    assert len(secret_findings) >= 1, "Hardcoded secrets in config.py must be detected"

    # Verify code slop
    slop_findings = [f for f in findings if f.category == "quality"]
    assert len(slop_findings) >= 1

    # Verify loose ends
    loose_findings = [f for f in findings if f.category == "loose_end"]
    assert len(loose_findings) >= 1


def test_finding_and_chain_ids_are_unique_across_audits(db_session):
    proj_data = ProjectService.create_project_from_demo()
    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type=proj_data["source_type"],
        source_url=proj_data["source_url"],
        root_path=proj_data["root_path"],
        meta_info=str(proj_data["meta_info"])
    )
    db_session.add(project)
    db_session.commit()
    service = AuditService(db_session)

    first_audit = service.run_audit(project.id)
    second_audit = service.run_audit(project.id)
    first_findings = {
        finding.id for finding in db_session.query(Finding)
        .filter(Finding.audit_id == first_audit.id)
    }
    second_findings = {
        finding.id for finding in db_session.query(Finding)
        .filter(Finding.audit_id == second_audit.id)
    }
    first_chains = {
        chain.id for chain in db_session.query(VulnerabilityChain)
        .filter(VulnerabilityChain.audit_id == first_audit.id)
    }
    second_chains = {
        chain.id for chain in db_session.query(VulnerabilityChain)
        .filter(VulnerabilityChain.audit_id == second_audit.id)
    }

    assert first_findings.isdisjoint(second_findings)
    assert first_chains.isdisjoint(second_chains)

def test_remediation_preview_and_diff(db_session):
    proj_data = ProjectService.create_project_from_demo()
    project = Project(
        id=proj_data["id"],
        name=proj_data["name"],
        description=proj_data["description"],
        source_type=proj_data["source_type"],
        source_url=proj_data["source_url"],
        root_path=proj_data["root_path"],
        meta_info=str(proj_data["meta_info"])
    )
    db_session.add(project)
    db_session.commit()
    audit = AuditService(db_session).run_audit(project.id)

    finding = db_session.query(Finding).filter(
        Finding.audit_id == audit.id,
        Finding.title.ilike("%sql%")
    ).first()
    assert finding is not None

    engine = RemediationEngine(project.root_path)
    patch = engine.generate_patch({
        "id": finding.id,
        "title": finding.title,
        "category": finding.category,
        "file_path": finding.file_path,
        "snippet": finding.snippet,
        "description": finding.description
    })

    assert patch["unified_diff"] != ""
    assert "?" in patch["patched_code"]
    assert "cursor.execute" in patch["patched_code"]

def test_report_generation(db_session):
    audit = db_session.query(Audit).filter(Audit.status == "completed").first()
    assert audit is not None
    project = db_session.query(Project).filter(Project.id == audit.project_id).first()
    findings = db_session.query(Finding).filter(Finding.audit_id == audit.id).all()
    chains = db_session.query(VulnerabilityChain).filter(VulnerabilityChain.audit_id == audit.id).all()

    audit_dict = {"id": audit.id, "security_score": audit.security_score, "engineering_health_score": audit.engineering_health_score}
    project_dict = {"name": project.name, "id": project.id}
    findings_list = [{"id": f.id, "title": f.title, "severity": f.severity, "file_path": f.file_path, "start_line": f.start_line, "recommendation": f.recommendation} for f in findings]
    chains_list = [{"id": c.id, "title": c.title, "severity": c.severity, "confidence": c.confidence, "source_file": c.source_file, "source_line": c.source_line, "sink_file": c.sink_file, "sink_line": c.sink_line, "description": c.description, "remediation_summary": c.remediation_summary} for c in chains]

    html = ReportGenerator.generate_html(audit_dict, project_dict, findings_list, chains_list)
    assert "<!DOCTYPE html>" in html
    assert "CodeSentinel" in html

    md = ReportGenerator.generate_markdown(audit_dict, project_dict, findings_list, chains_list)
    assert "# CodeSentinel AI" in md

    js = ReportGenerator.generate_json(audit_dict, project_dict, findings_list, chains_list)
    assert "CodeSentinel AI" in js
