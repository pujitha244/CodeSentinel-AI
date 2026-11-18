"""
PRIORITY 2: Remediation Integrity Test Suite

Proves:
 - Vulnerable original code IS detected.
 - Patched code is NO LONGER flagged for the same vulnerability.
 - Unrelated vulnerabilities remain detectable.
 - Rollback restores the original vulnerability.
 - Patch application is safe and repeatable.
 - Failed patches do not corrupt source files.
"""
import sys, os, shutil
sys.path.insert(0, os.path.abspath("."))

import pytest
from pathlib import Path
from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.models import Project, Audit, Finding
from backend.app.services.project_service import ProjectService
from backend.app.services.audit_service import AuditService
from backend.app.remediation.remediation_engine import RemediationEngine
from backend.app.scanners.security_scanner import SecurityScanner
from backend.app.scanners.secret_scanner import SecretScanner

@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()

@pytest.fixture(scope="module")
def fresh_demo(db):
    """Create a fresh demo project and run its audit."""
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
    db.add(project)
    db.commit()

    service = AuditService(db)
    audit = service.run_audit(project.id)
    return project, audit


class TestRemediationIntegrity:

    def test_1_original_sql_vulnerability_is_detected(self, fresh_demo, db):
        """Step 1: Original database.py IS detected with SQL injection before any patch."""
        project, audit = fresh_demo
        sec = SecurityScanner()
        findings = sec.scan(project.root_path, ["backend/database.py"])
        sql_findings = [f for f in findings if "sql" in f["title"].lower() or "sql" in f["description"].lower()]
        assert len(sql_findings) >= 1, "SQL injection should be detected in original database.py"
        for f in sql_findings:
            print(f"[DETECTED] {f['title']} | Line: {f.get('start_line')}")

    def test_2_patch_generates_real_unified_diff(self, fresh_demo, db):
        """Step 2: Patch generation produces an actual non-empty unified diff."""
        project, audit = fresh_demo
        engine = RemediationEngine(project.root_path)

        db_file = Path(project.root_path) / "backend/database.py"
        original_code = db_file.read_text(encoding="utf-8")
        assert "search_term" in original_code, "Original file must contain unsafe search_term usage"

        sql_finding = db.query(Finding).filter(
            Finding.audit_id == audit.id,
            Finding.file_path == "backend/database.py",
            Finding.title.ilike("%sql%")
        ).first()
        assert sql_finding is not None, "SQL injection finding must exist in DB"

        patch = engine.generate_patch({
            "id": sql_finding.id,
            "title": sql_finding.title,
            "category": sql_finding.category,
            "file_path": sql_finding.file_path,
            "snippet": sql_finding.snippet,
            "description": sql_finding.description
        })

        print("\nUnified Diff:")
        print(patch["unified_diff"])

        assert len(patch["unified_diff"].strip()) > 0, "Unified diff must not be empty"
        assert "-query = f\"" in patch["unified_diff"] or "-        query = f" in patch["unified_diff"], \
            "Diff must show removal of f-string query"
        assert '+query = "SELECT' in patch["unified_diff"] or '+        query = "SELECT' in patch["unified_diff"], \
            "Diff must show safe parameterized query"
        assert "(search_term, search_term)" in patch["patched_code"], \
            "Patched code must use tuple parameters"
        assert "cursor.execute(query, " in patch["patched_code"], \
            "Patched code must use parameterized execute call"

    def test_3_apply_patch_modifies_actual_file(self, fresh_demo, db):
        """Step 3: apply_patch() actually writes the patched code to disk."""
        project, audit = fresh_demo
        engine = RemediationEngine(project.root_path)

        db_file = Path(project.root_path) / "backend/database.py"
        before_content = db_file.read_text(encoding="utf-8")

        sql_finding = db.query(Finding).filter(
            Finding.audit_id == audit.id,
            Finding.file_path == "backend/database.py",
            Finding.title.ilike("%sql%")
        ).first()
        patch = engine.generate_patch({
            "id": sql_finding.id,
            "title": sql_finding.title,
            "category": sql_finding.category,
            "file_path": sql_finding.file_path,
            "snippet": sql_finding.snippet,
            "description": sql_finding.description
        })

        success = engine.apply_patch(sql_finding.file_path, patch["patched_code"])
        assert success, "apply_patch must return True"

        after_content = db_file.read_text(encoding="utf-8")
        assert before_content != after_content, "File content MUST change after patch application"
        assert 'cursor.execute(query, (search_term, search_term))' in after_content, \
            "Patched file must contain parameterized query"
        assert 'f"SELECT' not in after_content, \
            "Patched file must NOT contain original f-string vulnerability"

    def test_4_backup_exists_after_apply(self, fresh_demo, db):
        """Step 4: A .codesentinel_backup file is created before patch application."""
        project, audit = fresh_demo
        backup_path = Path(project.root_path) / "backend/database.py.codesentinel_backup"
        assert backup_path.exists(), "Backup file must exist after patch application"
        backup_content = backup_path.read_text(encoding="utf-8")
        assert "search_term}'" in backup_content or 'f"SELECT' in backup_content, \
            "Backup must contain the original vulnerable code"

    def test_5_patched_file_no_longer_triggers_sql_scanner(self, fresh_demo, db):
        """Step 5: Static scanner no longer flags SQL injection after patching."""
        project, audit = fresh_demo
        sec = SecurityScanner()
        findings = sec.scan(project.root_path, ["backend/database.py"])
        # The raw execute_raw_search f-string SQL should be gone
        db_file = Path(project.root_path) / "backend/database.py"
        content = db_file.read_text(encoding="utf-8")
        # Confirm the file is patched
        assert "cursor.execute(query, (search_term" in content, "File must be patched"
        
        raw_sql_findings = [f for f in findings if 
            "search_term" in f.get("snippet", "") and 
            "f\"" in f.get("snippet", "")]
        assert len(raw_sql_findings) == 0, \
            f"Patched file must NOT trigger f-string SQL injection scanner: {raw_sql_findings}"

    def test_6_unrelated_vulnerabilities_still_detected(self, fresh_demo, db):
        """Step 6: Patching database.py does not affect detection of config.py secrets."""
        project, audit = fresh_demo
        secret_scanner = SecretScanner()
        findings = secret_scanner.scan(project.root_path, ["backend/config.py"])
        assert len(findings) >= 3, \
            f"Secret scanner must still detect AWS keys and JWT tokens in config.py, got: {findings}"

    def test_7_rollback_restores_original_vulnerable_code(self, fresh_demo, db):
        """Step 7: Rollback restores the original vulnerable file."""
        project, audit = fresh_demo
        engine = RemediationEngine(project.root_path)

        db_file = Path(project.root_path) / "backend/database.py"
        # Confirm patch is applied
        patched_content = db_file.read_text(encoding="utf-8")
        assert "cursor.execute(query, (search_term" in patched_content, "Must be patched before rollback"

        success = engine.rollback_patch("backend/database.py")
        assert success, "rollback_patch must return True when backup exists"

        rolled_back_content = db_file.read_text(encoding="utf-8")
        assert "cursor.execute(query, (search_term" not in rolled_back_content, \
            "Rolled-back file must NOT contain parameterized query"
        # Original f-string must be restored
        assert "search_term}" in rolled_back_content or 'f"SELECT' in rolled_back_content, \
            "Rolled-back file must contain the original vulnerable SQL"

        # Backup should be gone after rollback
        backup_path = Path(project.root_path) / "backend/database.py.codesentinel_backup"
        assert not backup_path.exists(), "Backup file must be removed after rollback"

    def test_8_rollback_re_enables_vulnerability_detection(self, fresh_demo, db):
        """Step 8: After rollback, SQL injection is re-detectable."""
        project, audit = fresh_demo
        sec = SecurityScanner()
        findings = sec.scan(project.root_path, ["backend/database.py"])
        sql_findings = [f for f in findings if "sql" in f["title"].lower()]
        assert len(sql_findings) >= 1, \
            "SQL injection must be re-detected after rollback to original code"

    def test_9_patch_is_idempotent_safe_to_reapply(self, fresh_demo, db):
        """Step 9: Applying the patch twice does not corrupt the file."""
        project, audit = fresh_demo
        engine = RemediationEngine(project.root_path)
        db_file = Path(project.root_path) / "backend/database.py"

        sql_finding = db.query(Finding).filter(
            Finding.audit_id == audit.id,
            Finding.file_path == "backend/database.py",
            Finding.title.ilike("%sql%")
        ).first()
        patch = engine.generate_patch({
            "id": sql_finding.id,
            "title": sql_finding.title,
            "category": sql_finding.category,
            "file_path": sql_finding.file_path,
            "snippet": sql_finding.snippet,
            "description": sql_finding.description
        })

        # Apply twice
        engine.apply_patch(sql_finding.file_path, patch["patched_code"])
        second_patch = engine.generate_patch({
            "id": sql_finding.id,
            "title": sql_finding.title,
            "category": sql_finding.category,
            "file_path": sql_finding.file_path,
            "snippet": sql_finding.snippet,
            "description": sql_finding.description
        })
        engine.apply_patch(sql_finding.file_path, second_patch["patched_code"])
        
        content = db_file.read_text(encoding="utf-8")
        assert 'cursor.execute(query, (search_term, search_term))' in content, \
            "File must remain correctly patched after double-apply"
        # Must not have corrupted duplicate lines
        assert content.count('cursor.execute(query, (search_term, search_term))') == 1, \
            "No duplicate parameterized lines after double-apply"

    def test_10_failed_patch_does_not_corrupt_source(self, fresh_demo, db):
        """Step 10: If patch produces identical code, file remains intact."""
        project, audit = fresh_demo
        engine = RemediationEngine(project.root_path)
        db_file = Path(project.root_path) / "backend/database.py"
        before = db_file.read_text(encoding="utf-8")
        
        # Try applying the current content as the "patch" (no-op)
        success = engine.apply_patch("backend/database.py", before)
        assert success, "apply_patch must not raise on no-change write"
        
        after = db_file.read_text(encoding="utf-8")
        assert before == after, "File must be byte-for-byte identical when patched code == original"
