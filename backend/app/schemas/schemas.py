from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- Project Schemas ---
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = ""

class ProjectCreate(ProjectBase):
    source_type: str = "upload"
    source_url: Optional[str] = ""

class ProjectResponse(ProjectBase):
    id: str
    source_type: str
    source_url: Optional[str] = ""
    root_path: str
    created_at: datetime
    meta_info: Dict[str, Any] = {}

    class Config:
        from_attributes = True

class ProjectSummaryResponse(BaseModel):
    id: str
    name: str
    languages: List[str]
    frameworks: List[str]
    file_count: int
    line_count: int
    entry_points: List[str]
    latest_audit: Optional[Dict[str, Any]] = None

# --- Finding Schemas ---
class FindingResponse(BaseModel):
    id: str
    audit_id: str
    project_id: str
    title: str
    category: str
    severity: str
    confidence: float
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    description: str
    impact: str
    recommendation: str
    verification: str
    detection_method: str
    status: str
    chain_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# --- Vulnerability Chain Schemas ---
class ChainNode(BaseModel):
    id: str
    label: str
    type: str  # source, intermediate, boundary, sink
    file: str
    line: int
    function: Optional[str] = ""
    code_snippet: Optional[str] = ""
    description: Optional[str] = ""
    is_tainted: bool = True
    validation_status: Optional[str] = "unvalidated"

class ChainEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = ""
    data_flow: Optional[str] = ""
    relationship: str = "calls"  # calls, imports, passes_param, returns

class VulnerabilityChainResponse(BaseModel):
    id: str
    audit_id: str
    project_id: str
    title: str
    vulnerability_type: str
    severity: str
    confidence: float
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    description: str
    remediation_summary: str
    verified: bool
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    created_at: datetime

# --- Audit Schemas ---
class AuditCreate(BaseModel):
    project_id: str

class AuditResponse(BaseModel):
    id: str
    project_id: str
    status: str
    progress: int
    current_stage: str
    stages_log: List[str] = []
    security_score: float
    quality_score: float
    completeness_score: float
    engineering_health_score: float
    slop_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scanner_status: Dict[str, Any] = {}
    created_at: datetime
    completed_at: Optional[datetime] = None

# --- Remediation Schemas ---
class RemediationPreviewRequest(BaseModel):
    finding_id: str

class RemediationPatchResponse(BaseModel):
    patch_id: str
    finding_id: str
    file_path: str
    original_snippet: str
    replacement_snippet: str
    unified_diff: str
    explanation: str
    status: str
    verification_output: Optional[str] = ""

class RemediationApplyRequest(BaseModel):
    patch_id: str

class RemediationVerifyRequest(BaseModel):
    patch_id: str

# --- Assistant Schemas ---
class AssistantMessage(BaseModel):
    role: str
    content: str

class AssistantChatRequest(BaseModel):
    project_id: str
    audit_id: Optional[str] = None
    messages: List[AssistantMessage]

class AssistantChatResponse(BaseModel):
    reply: str
    evidence_references: List[Dict[str, Any]] = []

# --- Architecture Graph Schemas ---
class ArchitectureGraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    summary: Dict[str, Any]

# --- File Viewer Schema ---
class FileContentResponse(BaseModel):
    file_path: str
    content: str
    language: str
    line_count: int
