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
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [latestAudit, setLatestAudit] = useState<Audit | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [chains, setChains] = useState<VulnerabilityChain[]>([]);
  const [isLoadingDemo, setIsLoadingDemo] = useState(false);

  // Initialize data on mount
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      const projects = await api.listProjects();
      if (projects.length > 0) {
        const proj = projects[0];
        setCurrentProject(proj);
        
        const audits = await api.listAudits(proj.id);
        if (audits.length > 0) {
          const audit = audits[0];
          setLatestAudit(audit);

          const f = await api.getFindings(audit.id);
          setFindings(f);

          const c = await api.getVulnerabilityChains(proj.id);
          setChains(c);
        }
      }
    } catch (err) {
      console.error('Initialization error:', err);
    }
  };

  const handleLoadDemo = async () => {
    setIsLoadingDemo(true);
    try {
      const proj = await api.loadDemo();
      setCurrentProject(proj);

      const audit = await api.createAudit(proj.id);
      setLatestAudit(audit);

      const f = await api.getFindings(audit.id);
      setFindings(f);

      const c = await api.getVulnerabilityChains(proj.id);
      setChains(c);

      setIsLoadingDemo(false);
      navigate('/dashboard');
    } catch (err) {
      console.error('Demo launch error:', err);
      setIsLoadingDemo(false);
    }
  };

  const handleAuditComplete = (proj: Project, audit: Audit) => {
    setCurrentProject(proj);
    setLatestAudit(audit);
    api.getFindings(audit.id).then(setFindings);
    api.getVulnerabilityChains(proj.id).then(setChains);
  };

  return (
    <div className="min-h-screen bg-sentinel-950 text-slate-100 flex flex-col">
      <Navbar
        currentProject={currentProject}
        onLoadDemo={handleLoadDemo}
        isLoadingDemo={isLoadingDemo}
      />
      
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 overflow-y-auto min-h-[calc(100vh-4rem)]">
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
