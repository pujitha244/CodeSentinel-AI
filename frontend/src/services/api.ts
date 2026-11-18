import { 
  Project, Audit, Finding, VulnerabilityChain, 
  RemediationPatch, AssistantMessage, ArchitectureGraph 
} from '../types';

const API_BASE = '/api';

function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  return fetch(input, { ...init, credentials: 'include' });
}

/**
 * Safe response handler that guards against non-JSON / plain-text responses
 * (e.g. 500 Internal Server Error, proxy errors, network failures)
 */
async function handleResponse<T>(res: Response, fallbackErrorMsg = 'Request failed'): Promise<T> {
  const contentType = res.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (!res.ok) {
    let errorDetail = `${fallbackErrorMsg} (HTTP ${res.status})`;
    try {
      if (isJson) {
        const data = await res.json();
        if (typeof data.detail === 'string') {
          errorDetail = data.detail;
        } else if (Array.isArray(data.detail)) {
          errorDetail = data.detail.map((e: any) => e.msg || JSON.stringify(e)).join(', ');
        } else if (data.message) {
          errorDetail = data.message;
        } else {
          errorDetail = JSON.stringify(data);
        }
      } else {
        const text = await res.text();
        if (text && text.trim().length > 0) {
          errorDetail = text.length > 250 ? text.slice(0, 250) + '...' : text;
        }
      }
    } catch {
      // keep fallback
    }
    throw new Error(errorDetail);
  }

  if (isJson) {
    try {
      return (await res.json()) as T;
    } catch (e: any) {
      throw new Error(`Invalid JSON response received: ${e.message}`);
    }
  }

  const text = await res.text();
  return text as unknown as T;
}

export const api = {
  // Health
  async getHealth(): Promise<{ status: string; version: string; service: string; ai_provider: string }> {
    const res = await apiFetch(`${API_BASE}/health`);
    return handleResponse(res, 'Health check failed');
  },

  async getAuthSession(): Promise<{ configured: boolean; authenticated: boolean }> {
    const res = await apiFetch(`${API_BASE}/auth/session`);
    return handleResponse(res, 'Failed to check authentication status');
  },

  async createAuthSession(token: string): Promise<{ authenticated: boolean }> {
    const res = await apiFetch(`${API_BASE}/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    return handleResponse(res, 'Sign-in failed');
  },

  async deleteAuthSession(): Promise<void> {
    const res = await apiFetch(`${API_BASE}/auth/session`, { method: 'DELETE' });
    await handleResponse<{ authenticated: boolean }>(res, 'Sign-out failed');
  },

  // Projects
  async loadDemo(): Promise<Project> {
    const res = await apiFetch(`${API_BASE}/projects/demo`, { method: 'POST' });
    return handleResponse<Project>(res, 'Failed to load demo project');
  },

  async uploadZip(file: File): Promise<Project> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiFetch(`${API_BASE}/projects/upload`, {
      method: 'POST',
      body: formData
    });
    return handleResponse<Project>(res, 'Upload failed');
  },

  async ingestGithub(repoUrl: string, token?: string): Promise<Project> {
    const formData = new FormData();
    formData.append('repo_url', repoUrl);
    if (token) formData.append('token', token);
    const res = await apiFetch(`${API_BASE}/projects/github`, {
      method: 'POST',
      body: formData
    });
    return handleResponse<Project>(res, 'GitHub ingestion failed');
  },

  async listProjects(): Promise<Project[]> {
    const res = await apiFetch(`${API_BASE}/projects`);
    return handleResponse<Project[]>(res, 'Failed to list projects');
  },

  async getProject(projectId: string): Promise<Project> {
    const res = await apiFetch(`${API_BASE}/projects/${projectId}`);
    return handleResponse<Project>(res, 'Failed to fetch project');
  },

  async getProjectSummary(projectId: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/projects/${projectId}/summary`);
    return handleResponse(res, 'Failed to fetch project summary');
  },

  async getArchitectureGraph(projectId: string): Promise<ArchitectureGraph> {
    const res = await apiFetch(`${API_BASE}/projects/${projectId}/graph`);
    return handleResponse<ArchitectureGraph>(res, 'Failed to fetch architecture graph');
  },

  async getVulnerabilityChains(projectId: string): Promise<VulnerabilityChain[]> {
    const res = await apiFetch(`${API_BASE}/projects/${projectId}/vulnerability-chains`);
    return handleResponse<VulnerabilityChain[]>(res, 'Failed to fetch vulnerability chains');
  },

  // Audits
  async createAudit(projectId: string): Promise<Audit> {
    const res = await apiFetch(`${API_BASE}/audits`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId })
    });
    return handleResponse<Audit>(res, 'Failed to launch audit');
  },

  async listAudits(projectId?: string): Promise<Audit[]> {
    const url = projectId ? `${API_BASE}/audits?project_id=${projectId}` : `${API_BASE}/audits`;
    const res = await apiFetch(url);
    return handleResponse<Audit[]>(res, 'Failed to list audits');
  },

  async getAudit(auditId: string): Promise<Audit> {
    const res = await apiFetch(`${API_BASE}/audits/${auditId}`);
    return handleResponse<Audit>(res, 'Failed to fetch audit');
  },

  async getAuditStatus(auditId: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/audits/${auditId}/status`);
    return handleResponse(res, 'Failed to fetch audit status');
  },

  async getFindings(auditId: string, filters?: { category?: string; severity?: string; search?: string }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.category) params.set('category', filters.category);
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.search) params.set('search', filters.search);
    const res = await apiFetch(`${API_BASE}/audits/${auditId}/findings?${params.toString()}`);
    return handleResponse<Finding[]>(res, 'Failed to fetch findings');
  },

  // Findings & Explanations
  async getFinding(findingId: string): Promise<Finding> {
    const res = await apiFetch(`${API_BASE}/findings/${findingId}`);
    return handleResponse<Finding>(res, 'Failed to fetch finding');
  },

  async explainFinding(findingId: string): Promise<{ finding_id: string; explanation: string }> {
    const res = await apiFetch(`${API_BASE}/findings/${findingId}/explain`, { method: 'POST' });
    return handleResponse<{ finding_id: string; explanation: string }>(res, 'Failed to generate explanation');
  },

  // Safe Auto-Fix Remediation Lab
  async previewRemediation(findingId: string): Promise<RemediationPatch> {
    const res = await apiFetch(`${API_BASE}/remediation/${findingId}/preview`, { method: 'POST' });
    return handleResponse<RemediationPatch>(res, 'Failed to generate remediation patch');
  },

  async applyRemediation(findingId: string, patchId: string, patchedCode: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/remediation/${findingId}/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patch_id: patchId, patched_code: patchedCode })
    });
    return handleResponse(res, 'Failed to apply remediation patch');
  },

  async verifyRemediation(findingId: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/remediation/${findingId}/verify`, { method: 'POST' });
    return handleResponse(res, 'Failed to verify remediation');
  },

  async rollbackRemediation(findingId: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/remediation/${findingId}/rollback`, { method: 'POST' });
    return handleResponse(res, 'Failed to rollback remediation');
  },

  // File Viewer
  async getFileContent(projectId: string, filePath: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/files/content?project_id=${projectId}&file_path=${encodeURIComponent(filePath)}`);
    return handleResponse(res, 'File not accessible');
  },

  // AI Assistant
  async chatWithAssistant(projectId: string, auditId: string | null, messages: AssistantMessage[]): Promise<any> {
    const res = await apiFetch(`${API_BASE}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, audit_id: auditId, messages })
    });
    return handleResponse(res, 'Assistant communication failed');
  },

  // Reports
  getReportHtmlUrl(auditId: string): string {
    return `${API_BASE}/reports/${auditId}/html`;
  },

  async getReportMarkdown(auditId: string): Promise<string> {
    const res = await apiFetch(`${API_BASE}/reports/${auditId}/markdown`);
    return handleResponse<string>(res, 'Failed to fetch markdown report');
  },

  async getReportJson(auditId: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/reports/${auditId}/json`);
    return handleResponse(res, 'Failed to fetch JSON report');
  }
};
