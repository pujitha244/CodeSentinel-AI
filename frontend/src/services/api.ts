import { 
  Project, Audit, Finding, VulnerabilityChain, 
  RemediationPatch, AssistantMessage, ArchitectureGraph 
} from '../types';

const API_BASE = '/api';

export const api = {
  // Health
  async getHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  // Projects
  async loadDemo(): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/demo`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to load demo project');
    return res.json();
  },

  async uploadZip(file: File): Promise<Project> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/projects/upload`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async ingestGithub(repoUrl: string, token?: string): Promise<Project> {
    const formData = new FormData();
    formData.append('repo_url', repoUrl);
    if (token) formData.append('token', token);
    const res = await fetch(`${API_BASE}/projects/github`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'GitHub ingestion failed');
    }
    return res.json();
  },

  async listProjects(): Promise<Project[]> {
    const res = await fetch(`${API_BASE}/projects`);
    return res.json();
  },

  async getProject(projectId: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${projectId}`);
    return res.json();
  },

  async getProjectSummary(projectId: string) {
    const res = await fetch(`${API_BASE}/projects/${projectId}/summary`);
    return res.json();
  },

  async getArchitectureGraph(projectId: string): Promise<ArchitectureGraph> {
    const res = await fetch(`${API_BASE}/projects/${projectId}/graph`);
    return res.json();
  },

  async getVulnerabilityChains(projectId: string): Promise<VulnerabilityChain[]> {
    const res = await fetch(`${API_BASE}/projects/${projectId}/vulnerability-chains`);
    return res.json();
  },

  // Audits
  async createAudit(projectId: string): Promise<Audit> {
    const res = await fetch(`${API_BASE}/audits`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId })
    });
    if (!res.ok) throw new Error('Failed to launch audit');
    return res.json();
  },

  async listAudits(projectId?: string): Promise<Audit[]> {
    const url = projectId ? `${API_BASE}/audits?project_id=${projectId}` : `${API_BASE}/audits`;
    const res = await fetch(url);
    return res.json();
  },

  async getAudit(auditId: string): Promise<Audit> {
    const res = await fetch(`${API_BASE}/audits/${auditId}`);
    return res.json();
  },

  async getAuditStatus(auditId: string) {
    const res = await fetch(`${API_BASE}/audits/${auditId}/status`);
    return res.json();
  },

  async getFindings(auditId: string, filters?: { category?: string; severity?: string; search?: string }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.category) params.set('category', filters.category);
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.search) params.set('search', filters.search);
    const res = await fetch(`${API_BASE}/audits/${auditId}/findings?${params.toString()}`);
    return res.json();
  },

  // Findings & Explanations
  async getFinding(findingId: string): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${findingId}`);
    return res.json();
  },

  async explainFinding(findingId: string): Promise<{ finding_id: string; explanation: string }> {
    const res = await fetch(`${API_BASE}/findings/${findingId}/explain`, { method: 'POST' });
    return res.json();
  },

  // Safe Auto-Fix Remediation Lab
  async previewRemediation(findingId: string): Promise<RemediationPatch> {
    const res = await fetch(`${API_BASE}/remediation/${findingId}/preview`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to generate remediation patch');
    return res.json();
  },

  async applyRemediation(findingId: string, patchId: string, patchedCode: string) {
    const res = await fetch(`${API_BASE}/remediation/${findingId}/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patch_id: patchId, patched_code: patchedCode })
    });
    return res.json();
  },

  async verifyRemediation(findingId: string) {
    const res = await fetch(`${API_BASE}/remediation/${findingId}/verify`, { method: 'POST' });
    return res.json();
  },

  async rollbackRemediation(findingId: string) {
    const res = await fetch(`${API_BASE}/remediation/${findingId}/rollback`, { method: 'POST' });
    return res.json();
  },

  // File Viewer
  async getFileContent(projectId: string, filePath: string) {
    const res = await fetch(`${API_BASE}/files/content?project_id=${projectId}&file_path=${encodeURIComponent(filePath)}`);
    if (!res.ok) throw new Error('File not accessible');
    return res.json();
  },

  // AI Assistant
  async chatWithAssistant(projectId: string, auditId: string | null, messages: AssistantMessage[]) {
    const res = await fetch(`${API_BASE}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, audit_id: auditId, messages })
    });
    return res.json();
  },

  // Reports
  getReportHtmlUrl(auditId: string) {
    return `${API_BASE}/reports/${auditId}/html`;
  },

  async getReportMarkdown(auditId: string): Promise<string> {
    const res = await fetch(`${API_BASE}/reports/${auditId}/markdown`);
    return res.text();
  },

  async getReportJson(auditId: string) {
    const res = await fetch(`${API_BASE}/reports/${auditId}/json`);
    return res.json();
  }
};
