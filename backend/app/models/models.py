import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, default="")
    source_type = Column(String, default="upload")  # 'upload', 'github', 'demo'
    source_url = Column(String, default="")
    root_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Serialized metadata (languages, frameworks, files, entry points)
    meta_info = Column(Text, default="{}")

    audits = relationship("Audit", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    vulnerability_chains = relationship("VulnerabilityChain", back_populates="project", cascade="all, delete-orphan")

    def get_meta(self):
        try:
            return json.loads(self.meta_info)
        except Exception:
            return {}

    def set_meta(self, data: dict):
        self.meta_info = json.dumps(data)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(String, primary_key=True)
    expires_at = Column(Integer, nullable=False)
    revoked_at = Column(Integer, nullable=True)


class Audit(Base):
    __tablename__ = "audits"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    status = Column(String, default="queued")  # queued, running, completed, failed
    progress = Column(Integer, default=0)
    current_stage = Column(String, default="Initializing")
    stages_log = Column(Text, default="[]")
    
    # Calculated scores (0 - 100)
    security_score = Column(Float, default=100.0)
    quality_score = Column(Float, default=100.0)
    completeness_score = Column(Float, default=100.0)
    engineering_health_score = Column(Float, default=100.0)
    slop_score = Column(Float, default=0.0)
    
    # Counts
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    scanner_status = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="audits")
    findings = relationship("Finding", back_populates="audit", cascade="all, delete-orphan")
    vulnerability_chains = relationship("VulnerabilityChain", back_populates="audit", cascade="all, delete-orphan")

    @property
    def stages(self):
        try:
            return json.loads(self.stages_log or "[]")
        except Exception:
            return []

    @property
    def scanners(self):
        try:
            return json.loads(self.scanner_status or "{}")
        except Exception:
            return {}


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)  # CS-SEC-0001, CS-SLOP-0001, etc.
    audit_id = Column(String, ForeignKey("audits.id"), primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)  # security, quality, logic_gap, loose_end, secret, dependency
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    confidence = Column(Float, default=0.85)
    
    file_path = Column(String, nullable=False)
    start_line = Column(Integer, default=1)
    end_line = Column(Integer, default=1)
    snippet = Column(Text, default="")
    
    description = Column(Text, default="")
    impact = Column(Text, default="")
    recommendation = Column(Text, default="")
    verification = Column(Text, default="")
    
    detection_method = Column(String, default="ast_analyzer")
    status = Column(String, default="open")  # open, fixed, verified, ignored
    chain_id = Column(String, nullable=True)  # Associated vulnerability chain ID if applicable
    
    created_at = Column(DateTime, default=datetime.utcnow)

    audit = relationship("Audit", back_populates="findings")
    project = relationship("Project", back_populates="findings")


class VulnerabilityChain(Base):
    __tablename__ = "vulnerability_chains"

    id = Column(String, primary_key=True)  # CS-CHAIN-0001
    audit_id = Column(String, ForeignKey("audits.id"), primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    
    title = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False)  # sql_injection, command_injection, path_traversal, etc.
    severity = Column(String, default="critical")
    confidence = Column(Float, default=0.92)
    
    source_file = Column(String, nullable=False)
    source_line = Column(Integer, default=1)
    sink_file = Column(String, nullable=False)
    sink_line = Column(Integer, default=1)
    
    description = Column(Text, default="")
    remediation_summary = Column(Text, default="")
    verified = Column(Boolean, default=True)
    
    # React Flow graph representation: JSON arrays
    nodes_data = Column(Text, default="[]")
    edges_data = Column(Text, default="[]")
    
    created_at = Column(DateTime, default=datetime.utcnow)

    audit = relationship("Audit", back_populates="vulnerability_chains")
    project = relationship("Project", back_populates="vulnerability_chains")

    @property
    def nodes(self):
        try:
            return json.loads(self.nodes_data or "[]")
        except Exception:
            return []

    @property
    def edges(self):
        try:
            return json.loads(self.edges_data or "[]")
        except Exception:
            return []


class RemediationPatch(Base):
    __tablename__ = "remediation_patches"

    id = Column(String, primary_key=True, index=True)
    finding_id = Column(String, nullable=False)
    audit_id = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    
    original_snippet = Column(Text, default="")
    replacement_snippet = Column(Text, default="")
    unified_diff = Column(Text, default="")
    explanation = Column(Text, default="")
    
    status = Column(String, default="previewed")  # previewed, applied, verified, rolled_back
    verification_output = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
