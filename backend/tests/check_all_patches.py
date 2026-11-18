import sys, os
sys.path.insert(0, os.path.abspath("."))
from backend.app.core.database import SessionLocal
from backend.app.models.models import Finding, Project, Audit
from backend.app.remediation.remediation_engine import RemediationEngine

db = SessionLocal()
latest_audit = db.query(Audit).order_by(Audit.created_at.desc()).first()
print(f"Latest Audit: {latest_audit.id} (Project: {latest_audit.project_id})")

project = db.query(Project).filter(Project.id == latest_audit.project_id).first()
engine = RemediationEngine(project.root_path)

findings = db.query(Finding).filter(Finding.audit_id == latest_audit.id).all()
print(f"Total findings: {len(findings)}")

for f in findings:
    try:
        patch = engine.generate_patch({
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "file_path": f.file_path,
            "snippet": f.snippet,
            "description": f.description
        })
        diff_len = len(patch.get("unified_diff", ""))
        print(f"Finding: {f.id} | File: {f.file_path} | Title: {f.title[:50]} | Diff Length: {diff_len}")
        if diff_len == 0:
            print(f"  [EMPTY DIFF!] Category: {f.category} | File: {f.file_path}")
    except Exception as e:
        print(f"Finding: {f.id} | ERROR: {e}")
db.close()
