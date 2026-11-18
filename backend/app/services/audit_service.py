import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.models.models import Project, Audit, Finding, VulnerabilityChain
from backend.app.analyzers.ast_engine import CodeParser
from backend.app.analyzers.call_graph_builder import CallGraphBuilder
from backend.app.analyzers.taint_engine import TaintEngine
from backend.app.analyzers.code_slop_engine import CodeSlopEngine
from backend.app.analyzers.logic_gap_engine import LogicGapEngine
from backend.app.analyzers.loose_ends_engine import LooseEndsEngine
from backend.app.scanners.security_scanner import SecurityScanner
from backend.app.scanners.secret_scanner import SecretScanner
from backend.app.scanners.dependency_scanner import DependencyScanner
from backend.app.scanners.quality_scanner import QualityScanner
from backend.app.correlation.finding_correlator import FindingCorrelator

class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def run_audit(self, project_id: str) -> Audit:
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found.")

        audit_id = f"audit-{uuid.uuid4().hex[:8]}"
        audit = Audit(
            id=audit_id,
            project_id=project_id,
            status="running",
            progress=5,
            current_stage="1/17: Initializing repository audit pipeline",
            stages_log=json.dumps(["Pipeline initiated"]),
            created_at=datetime.utcnow()
        )
        self.db.add(audit)
        self.db.commit()
        self.db.refresh(audit)

        stages_log = []

        def log_stage(step: int, title: str, progress: int):
            msg = f"Step {step}/17: {title}"
            stages_log.append(msg)
            audit.current_stage = msg
            audit.progress = progress
            audit.stages_log = json.dumps(stages_log)
            self.db.commit()

        try:
            root_dir = project.root_path
            root_path = Path(root_dir).resolve()

            # Step 1: Repository validation
            log_stage(1, "Validating repository boundaries & paths", 10)
            if not root_path.exists():
                raise FileNotFoundError(f"Repository root {root_dir} does not exist.")

            # Step 2 & 3: File indexing & language detection
            log_stage(2, "Indexing files & detecting languages", 15)
            meta = project.get_meta()
            all_files = [f["path"] for f in meta.get("files", [])]
            if not all_files:
                from backend.app.services.project_service import ProjectService
                meta = ProjectService.inspect_project_structure(root_dir)
                project.set_meta(meta)
                self.db.commit()
                all_files = [f["path"] for f in meta.get("files", [])]

            # Step 4 & 5: Structural Analysis & AST extraction
            log_stage(4, "Parsing AST, classes, functions, and imports", 25)
            parsed_files: Dict[str, Any] = {}
            for rel_file in all_files:
                file_abs = root_path / rel_file
                if not file_abs.is_file():
                    continue
                try:
                    code = file_abs.read_text(encoding="utf-8", errors="ignore")
                    if rel_file.endswith(".py"):
                        parsed_files[rel_file] = CodeParser.parse_python(rel_file, code)
                    elif rel_file.endswith((".js", ".ts", ".jsx", ".tsx")):
                        parsed_files[rel_file] = CodeParser.parse_javascript(rel_file, code)
                except Exception:
                    continue

            # Step 6: Dependency Analysis
            log_stage(6, "Scanning dependencies for known CVE advisories", 35)
            dep_scanner = DependencyScanner()
            dep_findings = dep_scanner.scan(root_dir, all_files)

            # Step 7: Security Scanning
            log_stage(7, "Executing AST security analysis (SQLi, Command Injection, Traversal)", 45)
            sec_scanner = SecurityScanner()
            sec_findings = sec_scanner.scan(root_dir, all_files)

            # Step 8: Secret Detection
            log_stage(8, "Detecting exposed keys, tokens, and credentials (Gitleaks Engine)", 55)
            secret_scanner = SecretScanner()
            secret_findings = secret_scanner.scan(root_dir, all_files)

            # Step 9: Code Quality Analysis
            log_stage(9, "Analyzing code quality & Ruff-style standards", 62)
            qual_scanner = QualityScanner()
            qual_findings = qual_scanner.scan(root_dir, all_files)

            # Step 10 & 11: Call Graph & Architecture Linking
            log_stage(10, "Constructing cross-file call graph & module import map", 70)
            call_graph_builder = CallGraphBuilder(root_dir, parsed_files)
            call_graph_data = call_graph_builder.build()

            # Step 12: Code Slop Intelligence
            log_stage(12, "Evaluating Code Slop Index (dead code, duplication, nesting)", 75)
            slop_engine = CodeSlopEngine(root_dir, parsed_files, call_graph_data)
            slop_report = slop_engine.analyze()

            # Step 13: Logic Gaps & Edge Cases
            log_stage(13, "Hunting logic gaps & unhandled boundary conditions", 80)
            logic_gap_engine = LogicGapEngine(root_dir, parsed_files, call_graph_data)
            logic_gaps = logic_gap_engine.analyze()

            # Step 14: Loose Ends Detection
            log_stage(14, "Tracking TODOs, placeholder stubs, and loose ends", 85)
            loose_engine = LooseEndsEngine(root_dir, parsed_files, call_graph_data)
            loose_ends = loose_engine.analyze()

            # Step 15: Flagship Cross-File Vulnerability Chain Investigation
            log_stage(15, "Executing interprocedural taint propagation & chain analysis", 90)
            taint_engine = TaintEngine(root_dir, parsed_files, call_graph_data)
            vulnerability_chains = taint_engine.analyze()
            audit_suffix = audit_id.removeprefix("audit-")
            for chain in vulnerability_chains:
                chain_index = chain["id"].rsplit("-", 1)[-1]
                chain["id"] = f"CS-CHAIN-{audit_suffix}-{chain_index}"

            # Step 16: Correlation, Deduplication, and Risk Scoring
            log_stage(16, "Correlating findings & synthesizing parent vulnerability chains", 95)
            all_raw_findings = (
                sec_findings + secret_findings + dep_findings + 
                qual_findings + logic_gaps + loose_ends
            )

            correlated_findings, score_report = FindingCorrelator.correlate_and_deduplicate(
                all_raw_findings, vulnerability_chains, audit_id=audit_id
            )

            # Save Vulnerability Chains to DB
            for chain in vulnerability_chains:
                db_chain = VulnerabilityChain(
                    id=chain["id"],
                    audit_id=audit_id,
                    project_id=project_id,
                    title=chain["title"],
                    vulnerability_type=chain["vulnerability_type"],
                    severity=chain["severity"],
                    confidence=chain["confidence"],
                    source_file=chain["source_file"],
                    source_line=chain["source_line"],
                    sink_file=chain["sink_file"],
                    sink_line=chain["sink_line"],
                    description=chain["description"],
                    remediation_summary=chain["remediation_summary"],
                    verified=chain["verified"],
                    nodes_data=json.dumps(chain["nodes"]),
                    edges_data=json.dumps(chain["edges"]),
                    created_at=datetime.utcnow()
                )
                self.db.add(db_chain)

            # Save Correlated Findings to DB
            for f in correlated_findings:
                db_finding = Finding(
                    id=f["id"],
                    audit_id=audit_id,
                    project_id=project_id,
                    title=f["title"],
                    category=f.get("category", "security"),
                    severity=f.get("severity", "medium"),
                    confidence=f.get("confidence", 0.85),
                    file_path=f["file_path"],
                    start_line=f["start_line"],
                    end_line=f.get("end_line", f["start_line"]),
                    snippet=f.get("snippet", ""),
                    description=f.get("description", ""),
                    impact=f.get("impact", ""),
                    recommendation=f.get("recommendation", ""),
                    verification=f.get("verification", ""),
                    detection_method=f.get("detection_method", "ast_rules"),
                    status="open",
                    chain_id=f.get("chain_id"),
                    created_at=datetime.utcnow()
                )
                self.db.add(db_finding)

            # Step 17: Finalizing Audit Status & Scores
            log_stage(17, "Audit complete: scores computed and reports finalized", 100)
            audit.status = "completed"
            audit.completed_at = datetime.utcnow()
            audit.security_score = score_report["security_score"]
            audit.quality_score = score_report["quality_score"]
            audit.completeness_score = score_report["completeness_score"]
            audit.engineering_health_score = score_report["engineering_health_score"]
            audit.slop_score = slop_report["slop_score"]
            audit.total_findings = len(correlated_findings)
            audit.critical_count = score_report["counts"]["critical"]
            audit.high_count = score_report["counts"]["high"]
            audit.medium_count = score_report["counts"]["medium"]
            audit.low_count = score_report["counts"]["low"]
            audit.info_count = score_report["counts"]["info"]
            audit.scanner_status = json.dumps({
                "ast_engine": "active",
                "taint_engine": "active",
                "secret_scanner": "active",
                "dependency_scanner": "active",
                "quality_scanner": "active",
                "semgrep_installed": sec_scanner.semgrep_available,
                "bandit_installed": sec_scanner.bandit_available
            })

            self.db.commit()
            self.db.refresh(audit)
            return audit

        except Exception as e:
            audit.status = "failed"
            audit.current_stage = f"Audit failed: {str(e)}"
            stages_log.append(f"Fatal error: {str(e)}")
            audit.stages_log = json.dumps(stages_log)
            self.db.commit()
            raise e
