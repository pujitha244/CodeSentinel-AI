export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 'security' | 'secret' | 'quality' | 'logic_gap' | 'loose_end' | 'dependency';

export interface Project {
  id: string;
  name: string;
  description: string;
  source_type: 'upload' | 'github' | 'demo';
  source_url?: string;
  root_path: string;
  created_at: string;
  meta_info: {
    languages?: string[];
    frameworks?: string[];
    file_count?: number;
    line_count?: number;
    entry_points?: string[];
    files?: Array<{ path: string; extension: string; size_bytes: number; lines: number }>;
  };
}

export interface Audit {
  id: string;
  project_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  current_stage: string;
  stages_log: string[];
  security_score: number;
  quality_score: number;
  completeness_score: number;
  engineering_health_score: number;
  slop_score: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  scanner_status?: Record<string, any>;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  id: string;
  audit_id: string;
  project_id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: number;
  file_path: string;
  start_line: number;
  end_line: number;
  snippet: string;
  description: string;
  impact: string;
  recommendation: string;
  verification: string;
  detection_method: string;
  status: 'open' | 'fixed' | 'verified' | 'ignored';
  chain_id?: string | null;
  created_at: string;
}

export interface ChainNode {
  id: string;
  type: string;
  data: {
    label: string;
    kind: 'source' | 'intermediate' | 'boundary' | 'sink';
    file: string;
    line: number;
    function?: string;
    snippet?: string;
    description?: string;
    is_tainted?: boolean;
    badge?: string;
    badgeColor?: string;
  };
  position: { x: number; y: number };
}

export interface ChainEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
  type?: string;
  style?: Record<string, any>;
}

export interface VulnerabilityChain {
  id: string;
  audit_id: string;
  project_id: string;
  title: string;
  vulnerability_type: string;
  severity: Severity;
  confidence: number;
  source_file: string;
  source_line: number;
  sink_file: string;
  sink_line: number;
  description: string;
  remediation_summary: string;
  verified: boolean;
  nodes: ChainNode[];
  edges: ChainEdge[];
  created_at: string;
}

export interface RemediationPatch {
  patch_id: string;
  finding_id: string;
  file_path: string;
  original_snippet: string;
  replacement_snippet: string;
  unified_diff: string;
  original_code?: string;
  patched_code?: string;
  explanation: string;
  status: 'previewed' | 'applied' | 'verified' | 'rolled_back';
  verification_output?: string;
}

export interface AssistantMessage {
  role: 'user' | 'assistant';
  content: string;
  evidence_references?: Array<{ title: string; file: string; line: number }>;
}

export interface ArchitectureGraph {
  nodes: Array<{
    id: string;
    type: string;
    data: {
      label: string;
      kind: string;
      language?: string;
      functionCount?: number;
      importCount?: number;
    };
    position: { x: number; y: number };
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label?: string;
    animated?: boolean;
    style?: Record<string, any>;
  }>;
  summary: {
    file_count: number;
    function_count: number;
    edge_count: number;
  };
}
