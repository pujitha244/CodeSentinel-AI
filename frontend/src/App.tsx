import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { Project, Audit, Finding, VulnerabilityChain } from './types';
import { api } from './services/api';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { NewAuditPage } from './pages/NewAuditPage';
import { VulnerabilityChainPage } from './pages/VulnerabilityChainPage';
import { FindingsPage } from './pages/FindingsPage';
import { CodeQualityPage } from './pages/CodeQualityPage';
import { LogicGapsPage } from './pages/LogicGapsPage';
import { LooseEndsPage } from './pages/LooseEndsPage';
import { DependenciesPage } from './pages/DependenciesPage';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { RemediationLabPage } from './pages/RemediationLabPage';
import { AssistantPage } from './pages/AssistantPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

function AppContent() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [latestAudit, setLatestAudit] = useState<Audit | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [chains, setChains] = useState<VulnerabilityChain[]>([]);
  const [isLoadingDemo, setIsLoadingDemo] = useState(false);
  const [isSwitchingProject, setIsSwitchingProject] = useState(false);
  const [appError, setAppError] = useState<string | null>(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      const projects = await api.listProjects();
      setProjects(projects);
      if (projects.length > 0) {
        await handleSelectProject(projects[0].id, projects);
      }
    } catch (err) {
      console.error('Initialization error:', err);
      setAppError(err instanceof Error ? err.message : 'Unable to load saved projects.');
    }
  };

  const handleSelectProject = async (
    projectId: string,
    projectList: Project[] = projects
  ) => {
    const project = projectList.find((item) => item.id === projectId);
    if (!project) return;

    setIsSwitchingProject(true);
    setAppError(null);
    setCurrentProject(project);
    setLatestAudit(null);
    setFindings([]);
    setChains([]);
    try {
      const audits = await api.listAudits(project.id);
      if (audits.length > 0) {
        const audit = audits[0];
        const [projectFindings, projectChains] = await Promise.all([
          api.getFindings(audit.id),
          api.getVulnerabilityChains(project.id)
        ]);
        setLatestAudit(audit);
        setFindings(projectFindings);
        setChains(projectChains);
      }
    } catch (err) {
      console.error('Project selection error:', err);
      setAppError(err instanceof Error ? err.message : 'Unable to load project data.');
    } finally {
      setIsSwitchingProject(false);
    }
  };

  const handleLoadDemo = async () => {
    setIsLoadingDemo(true);
    setAppError(null);
    try {
      const proj = await api.loadDemo();
      setProjects((current) => [proj, ...current]);
      setCurrentProject(proj);

      const audit = await api.createAudit(proj.id);
      const [projectFindings, projectChains] = await Promise.all([
        api.getFindings(audit.id),
        api.getVulnerabilityChains(proj.id)
      ]);
      setLatestAudit(audit);
      setFindings(projectFindings);
      setChains(projectChains);
      navigate('/dashboard');
    } catch (err) {
      console.error('Demo launch error:', err);
      setAppError(err instanceof Error ? err.message : 'Unable to load the demo project.');
    } finally {
      setIsLoadingDemo(false);
    }
  };

  const handleAuditComplete = async (proj: Project, audit: Audit) => {
    setAppError(null);
    setProjects((current) =>
      current.some((item) => item.id === proj.id) ? current : [proj, ...current]
    );
    setCurrentProject(proj);
    setLatestAudit(audit);
    try {
      const [projectFindings, projectChains] = await Promise.all([
        api.getFindings(audit.id),
        api.getVulnerabilityChains(proj.id)
      ]);
      setFindings(projectFindings);
      setChains(projectChains);
    } catch (err) {
      console.error('Audit result loading error:', err);
      setAppError(err instanceof Error ? err.message : 'Audit completed but results could not be loaded.');
    }
  };

  return (
    <div className="min-h-screen bg-sentinel-950 text-slate-100 flex flex-col">
      <Navbar
        currentProject={currentProject}
        projects={projects}
        onSelectProject={(projectId) => handleSelectProject(projectId)}
        onLoadDemo={handleLoadDemo}
        isLoadingDemo={isLoadingDemo}
      />
      
      <div className="flex flex-1">
        <Sidebar />
        <main className="min-w-0 flex-1 overflow-y-auto min-h-[calc(100vh-3.5rem)]">
          {appError && (
            <div className="mx-6 mt-4 flex items-start justify-between gap-4 border border-rose-900/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200" role="alert">
              <span>{appError}</span>
              <button
                type="button"
                onClick={() => setAppError(null)}
                className="shrink-0 text-rose-300 underline underline-offset-2"
              >
                Dismiss
              </button>
            </div>
          )}
          {isSwitchingProject && (
            <div className="px-6 pt-3 text-xs text-slate-400" role="status">
              Loading selected project…
            </div>
          )}
          <Routes>
            <Route path="/" element={<LandingPage onLoadDemo={handleLoadDemo} isLoadingDemo={isLoadingDemo} />} />
            <Route
              path="/dashboard"
              element={
                <DashboardPage
                  currentProject={currentProject}
                  latestAudit={latestAudit}
                  chains={chains}
                  findings={findings}
                  onLoadDemo={handleLoadDemo}
                  isLoadingDemo={isLoadingDemo}
                />
              }
            />
            <Route path="/audit/new" element={<NewAuditPage onAuditComplete={handleAuditComplete} />} />
            <Route
              path="/chains"
              element={
                <VulnerabilityChainPage
                  currentProject={currentProject}
                  chains={chains}
                  onLoadDemo={handleLoadDemo}
                  isLoadingDemo={isLoadingDemo}
                />
              }
            />
            <Route path="/findings" element={<FindingsPage findings={findings} />} />
            <Route path="/quality" element={<CodeQualityPage latestAudit={latestAudit} findings={findings} />} />
            <Route path="/logic-gaps" element={<LogicGapsPage findings={findings} />} />
            <Route path="/loose-ends" element={<LooseEndsPage findings={findings} />} />
            <Route path="/dependencies" element={<DependenciesPage findings={findings} />} />
            <Route path="/architecture" element={<ArchitecturePage currentProject={currentProject} />} />
            <Route path="/remediation" element={<RemediationLabPage findings={findings} />} />
            <Route
              path="/assistant"
              element={<AssistantPage currentProject={currentProject} latestAudit={latestAudit} />}
            />
            <Route
              path="/reports"
              element={<ReportsPage currentProject={currentProject} latestAudit={latestAudit} />}
            />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;
