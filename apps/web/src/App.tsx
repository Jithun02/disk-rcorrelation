import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  FolderOpen,
  Cpu,
  FileText,
  Clock,
  Database,
  Globe,
  Settings,
  ChevronRight,
  TrendingUp,
  FileCode2,
  Trash2,
  UploadCloud,
  ChevronDown,
  User,
  LogOut,
  FolderLock
} from "lucide-react";

// Explorer Imports
import ProcessExplorer from "./components/ProcessExplorer";
import FilesystemExplorer from "./components/FilesystemExplorer";
import TimelineExplorer from "./components/TimelineExplorer";
import RegistryPersistence from "./components/RegistryPersistence";
import YaraLab from "./components/YaraLab";
import TriageAlerts from "./components/TriageAlerts";
import CaseNotesReports from "./components/CaseNotesReports";

export interface Case {
  id: number;
  name: string;
  description: string;
  investigator: string;
  status: string;
  created_at: string;
  updated_at: string;
  summary: any;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isStaticMode, setIsStaticMode] = useState<boolean>(
    typeof window !== "undefined" && (window.location.hostname.includes("github.io") || window.location.hostname.includes("localhost") === false)
  );

  // Default simulated case
  const defaultSimulationCase: Case = {
    id: 99,
    name: "Simulation Demo Case",
    description: "Default in-memory triage case. (Running in Client-Side Simulation Mode)",
    investigator: "Tier 3 Analyst",
    status: "Active",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    summary: {
      process_count: 39,
      disk_file_count: 36,
      deleted_file_count: 0,
      network_connection_count: 2
    }
  };
  
  // Case Form State
  const [showNewCaseModal, setShowNewCaseModal] = useState<boolean>(false);
  const [newCaseName, setNewCaseName] = useState<string>("");
  const [newCaseDesc, setNewCaseDesc] = useState<string>("");
  const [newCaseInvestigator, setNewCaseInvestigator] = useState<string>("");

  // Ingestion State
  const [ingestionName, setIngestionName] = useState<string>("");
  const [ingestionType, setIngestionType] = useState<"memory" | "disk">("memory");
  const [memoryFilePath, setMemoryFilePath] = useState<string>("data/best_public_memory.mem");
  const [diskFilePath, setDiskFilePath] = useState<string>("data/best_public_disk.001");
  const [ingestionMode, setIngestionMode] = useState<"live" | "simulation">("simulation");
  const [isIngesting, setIsIngesting] = useState<boolean>(false);
  const [ingestionLogs, setIngestionLogs] = useState<string>("");

  useEffect(() => {
    fetchCases();
  }, [isStaticMode]);

  const fetchCases = async () => {
    if (isStaticMode) {
      setCases(prev => prev.length ? prev : [defaultSimulationCase]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await fetch("/api/cases");
      if (res.ok) {
        const data = await res.json();
        setCases(data);
      } else {
        throw new Error("API unreachable");
      }
    } catch (err) {
      console.warn("Failed to reach API server. Falling back to Client-Side Simulation Mode.");
      setIsStaticMode(true);
      setCases([defaultSimulationCase]);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;

    if (isStaticMode) {
      const newMockCase: Case = {
        id: Math.floor(Math.random() * 1000) + 100,
        name: newCaseName,
        description: newCaseDesc + " (Simulated)",
        investigator: newCaseInvestigator || "Analyst",
        status: "Active",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        summary: {}
      };
      setCases(prev => [newMockCase, ...prev]);
      setShowNewCaseModal(false);
      setNewCaseName("");
      setNewCaseDesc("");
      setNewCaseInvestigator("");
      return;
    }

    try {
      const res = await fetch("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: newCaseName,
          description: newCaseDesc,
          investigator: newCaseInvestigator || "Analyst"
        })
      });
      if (res.ok) {
        setNewCaseName("");
        setNewCaseDesc("");
        setNewCaseInvestigator("");
        setShowNewCaseModal(false);
        fetchCases();
      }
    } catch (err) {
      console.error("Error creating case", err);
    }
  };

  const handleDeleteCase = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Are you sure you want to delete this case and all parsed evidence data?")) return;

    if (isStaticMode) {
      setCases(prev => prev.filter(c => c.id !== id));
      if (selectedCase?.id === id) {
        setSelectedCase(null);
      }
      return;
    }

    try {
      const res = await fetch(`/api/cases/${id}`, { method: "DELETE" });
      if (res.ok) {
        if (selectedCase?.id === id) {
          setSelectedCase(null);
        }
        fetchCases();
      }
    } catch (err) {
      console.error("Error deleting case", err);
    }
  };

  const handleIngestEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;
    setIsIngesting(true);
    setIngestionLogs("Submitting ingestion job to Node.js backend...");

    if (isStaticMode) {
      let step = 0;
      const logs = [
        "Scheduling job locally in browser context...",
        "Simulating pytsk3 recursive filesystem parsing...",
        "Found 36 file entries in disk sectors.",
        "Parsing windows.pslist structures with Volatility 3...",
        "Cross-referencing process addresses with psxview list...",
        "Identifying process injection anomalies...",
        "Compiling chronological super timeline logs...",
        "Forensic Ingestion Completed! Storing records to state..."
      ];
      
      const interval = setInterval(() => {
        if (step < logs.length) {
          setIngestionLogs(prev => prev + "\n" + logs[step]);
          step++;
        } else {
          clearInterval(interval);
          setIsIngesting(false);
          setIngestionName("");
          
          // Update case summary with simulated counts
          const updatedCase = {
            ...selectedCase,
            summary: {
              process_count: 39,
              disk_file_count: 36,
              deleted_file_count: 0,
              network_connection_count: 2
            }
          };
          setSelectedCase(updatedCase);
          setCases(prev => prev.map(c => c.id === selectedCase.id ? updatedCase : c));
          alert("Forensic Ingestion Completed successfully!");
          setActiveTab("dashboard");
        }
      }, 500);
      return;
    }

    try {
      const res = await fetch(`/api/cases/${selectedCase.id}/evidence`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: ingestionName || "Evidence Sample",
          type: ingestionType,
          memoryPath: memoryFilePath,
          diskPath: diskFilePath,
          mode: ingestionMode
        })
      });

      if (res.ok) {
        setIngestionLogs(prev => prev + "\nJob scheduled. Processing forensic headers...");
        // Poll for ingestion progress
        setTimeout(() => checkIngestionStatus(), 3000);
      } else {
        setIsIngesting(false);
        setIngestionLogs(prev => prev + "\nFailed to schedule job.");
      }
    } catch (err) {
      setIsIngesting(false);
      setIngestionLogs(prev => prev + `\nError running job: ${err}`);
    }
  };

  const checkIngestionStatus = async () => {
    if (!selectedCase) return;
    try {
      const res = await fetch(`/api/cases/${selectedCase.id}/evidence`);
      if (res.ok) {
        const items = await res.json();
        const latestJob = items[items.length - 1];
        if (latestJob) {
          setIngestionLogs(latestJob.logs || "Processing...");
          if (latestJob.status === "Completed") {
            setIsIngesting(false);
            setIngestionName("");
            // Refresh Case Summary
            const updatedCaseRes = await fetch(`/api/cases/${selectedCase.id}`);
            if (updatedCaseRes.ok) {
              const updatedCaseData = await updatedCaseRes.json();
              setSelectedCase(updatedCaseData);
            }
            alert("Forensic Ingestion Completed successfully!");
            setActiveTab("dashboard");
            fetchCases();
          } else if (latestJob.status === "Failed") {
            setIsIngesting(false);
            alert("Ingestion failed. Review Python standard output logs below.");
          } else {
            // Keep polling
            setTimeout(() => checkIngestionStatus(), 4000);
          }
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const renderContent = () => {
    if (!selectedCase) return renderCaseSelection();

    switch (activeTab) {
      case "dashboard":
        return renderDashboard();
      case "ingest":
        return renderIngestionWizard();
      case "processes":
        return <ProcessExplorer caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "filesystem":
        return <FilesystemExplorer caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "timeline":
        return <TimelineExplorer caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "registry":
        return <RegistryPersistence caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "alerts":
        return <TriageAlerts caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "yara":
        return <YaraLab caseId={selectedCase.id} isStatic={isStaticMode} />;
      case "notes":
        return <CaseNotesReports caseId={selectedCase.id} isStatic={isStaticMode} />;
      default:
        return renderDashboard();
    }
  };

  const renderCaseSelection = () => {
    return (
      <div className="flex-1 p-8 overflow-y-auto max-w-6xl mx-auto flex flex-col justify-center min-h-screen">
        <div className="flex justify-between items-center mb-8 border-b border-borderDark pb-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              <FolderLock className="w-8 h-8 text-brand-500" />
              ForensiCore XDR
            </h1>
            <p className="text-slate-400 mt-1">Enterprise Workstation & Forensic Evidence Locker</p>
          </div>
          <button
            onClick={() => setShowNewCaseModal(true)}
            className="px-4 py-2 bg-brand-500 hover:bg-brand-600 rounded text-sm font-semibold transition"
          >
            Create Investigation Case
          </button>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-brand-500 mb-4"></div>
            Loading database files...
          </div>
        ) : cases.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 bg-panel border border-borderDark rounded-lg text-center p-8">
            <FolderOpen className="w-16 h-16 text-slate-500 mb-4" />
            <h3 className="text-lg font-semibold text-white">No Forensic Cases Available</h3>
            <p className="text-slate-400 max-w-sm mt-2">
              Get started by creating your first forensic case to ingest memory images or disk dumps.
            </p>
            <button
              onClick={() => setShowNewCaseModal(true)}
              className="mt-5 px-4 py-2 bg-brand-500 hover:bg-brand-600 rounded text-sm font-semibold transition"
            >
              New Case
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {cases.map((c) => (
              <div
                key={c.id}
                onClick={() => setSelectedCase(c)}
                className="group relative bg-panel hover:bg-panel/80 border border-borderDark hover:border-brand-500/50 rounded-lg p-6 cursor-pointer transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex justify-between items-start">
                    <h3 className="text-lg font-semibold text-white group-hover:text-brand-500 transition">
                      {c.name}
                    </h3>
                    <button
                      onClick={(e) => handleDeleteCase(c.id, e)}
                      className="p-1.5 text-slate-500 hover:text-red-500 hover:bg-red-500/10 rounded transition"
                      title="Delete Case"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                  <p className="text-slate-400 text-sm mt-2 line-clamp-2">
                    {c.description || "No description provided."}
                  </p>
                </div>

                <div className="mt-6 pt-4 border-t border-borderDark/60 flex justify-between items-center text-xs text-slate-500">
                  <div>
                    Investigator: <span className="text-slate-300 font-medium">{c.investigator}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    <ChevronRight className="w-4 h-4 text-slate-400" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Create Case Modal */}
        {showNewCaseModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="bg-panel border border-borderDark rounded-lg p-6 max-w-md w-full shadow-xl">
              <h3 className="text-lg font-bold text-white mb-4">New Forensic Investigation Case</h3>
              <form onSubmit={handleCreateCase} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Case Name *
                  </label>
                  <input
                    type="text"
                    required
                    value={newCaseName}
                    onChange={(e) => setNewCaseName(e.target.value)}
                    placeholder="e.g. Host-A Triage T3-2026"
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Investigator Name
                  </label>
                  <input
                    type="text"
                    value={newCaseInvestigator}
                    onChange={(e) => setNewCaseInvestigator(e.target.value)}
                    placeholder="e.g. J. Doe (Incident Response)"
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Case Description / Scope
                  </label>
                  <textarea
                    rows={3}
                    value={newCaseDesc}
                    onChange={(e) => setNewCaseDesc(e.target.value)}
                    placeholder="Describe system impact, host names, timeline scopes..."
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500 resize-none"
                  />
                </div>
                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowNewCaseModal(false)}
                    className="px-4 py-2 border border-borderDark text-slate-400 rounded text-sm hover:text-white hover:bg-slate-800 transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-brand-500 hover:bg-brand-600 rounded text-sm font-semibold transition"
                  >
                    Create Case
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderDashboard = () => {
    const summary = selectedCase?.summary || {};
    
    return (
      <div className="flex-1 p-8 overflow-y-auto space-y-8">
        <div className="flex justify-between items-center border-b border-borderDark pb-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Case Workspace Dashboard</h1>
            <p className="text-slate-400 mt-1">Investigative summary and endpoint artifacts correlation</p>
          </div>
          <button
            onClick={() => setActiveTab("ingest")}
            className="px-4 py-2 bg-brand-500 hover:bg-brand-600 rounded text-sm font-semibold transition flex items-center gap-2"
          >
            <UploadCloud className="w-4 h-4" /> Ingest Evidence
          </button>
        </div>

        {/* Summary Metric Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-panel border border-borderDark rounded-lg p-5">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Memory Processes</p>
            <h3 className="text-3xl font-bold text-white mt-2 font-mono">{summary.process_count || 0}</h3>
          </div>
          <div className="bg-panel border border-borderDark rounded-lg p-5">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Filesystem Entries</p>
            <h3 className="text-3xl font-bold text-white mt-2 font-mono">{summary.disk_file_count || 0}</h3>
          </div>
          <div className="bg-panel border border-borderDark rounded-lg p-5">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Deleted Files</p>
            <h3 className="text-3xl font-bold text-white mt-2 font-mono text-severity-high">{summary.deleted_file_count || 0}</h3>
          </div>
          <div className="bg-panel border border-borderDark rounded-lg p-5">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Network Connections</p>
            <h3 className="text-3xl font-bold text-white mt-2 font-mono text-brand-500">{summary.network_connection_count || 0}</h3>
          </div>
        </div>

        {/* Dashboard Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Host/Case details */}
          <div className="bg-panel border border-borderDark rounded-lg p-6 lg:col-span-1 space-y-4">
            <h3 className="text-base font-semibold text-white">Locker Metadata</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between border-b border-borderDark/40 pb-2">
                <span className="text-slate-400">Case Name:</span>
                <span className="text-slate-200 font-semibold">{selectedCase?.name}</span>
              </div>
              <div className="flex justify-between border-b border-borderDark/40 pb-2">
                <span className="text-slate-400">Investigator:</span>
                <span className="text-slate-200">{selectedCase?.investigator}</span>
              </div>
              <div className="flex justify-between border-b border-borderDark/40 pb-2">
                <span className="text-slate-400">Status:</span>
                <span className="text-emerald-500 font-medium">{selectedCase?.status}</span>
              </div>
              <div className="flex justify-between border-b border-borderDark/40 pb-2">
                <span className="text-slate-400">Created:</span>
                <span className="text-slate-300">{selectedCase ? new Date(selectedCase.created_at).toLocaleString() : ""}</span>
              </div>
            </div>
            <div className="pt-2">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Scope Notes</h4>
              <p className="text-slate-300 text-sm bg-background border border-borderDark/60 rounded p-3 italic">
                {selectedCase?.description || "No scoping details compiled."}
              </p>
            </div>
          </div>

          {/* Quick Action Navigation panel */}
          <div className="bg-panel border border-borderDark rounded-lg p-6 lg:col-span-2 space-y-4 flex flex-col justify-between">
            <div>
              <h3 className="text-base font-semibold text-white mb-2">Forensic Triage Workbench</h3>
              <p className="text-slate-400 text-sm">
                Access specific workspace modules to run deep analysis over memory heaps and storage sectors.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => setActiveTab("processes")}
                className="p-4 bg-background border border-borderDark hover:border-brand-500/50 rounded-lg flex items-center gap-3 transition text-left group"
              >
                <div className="p-2 bg-brand-500/10 text-brand-500 rounded group-hover:bg-brand-500 group-hover:text-white transition">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-white">Process Tree</h4>
                  <p className="text-xs text-slate-500 mt-0.5">Volatilty cross-views</p>
                </div>
              </button>

              <button
                onClick={() => setActiveTab("filesystem")}
                className="p-4 bg-background border border-borderDark hover:border-brand-500/50 rounded-lg flex items-center gap-3 transition text-left group"
              >
                <div className="p-2 bg-brand-500/10 text-brand-500 rounded group-hover:bg-brand-500 group-hover:text-white transition">
                  <FolderOpen className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-white">Filesystem</h4>
                  <p className="text-xs text-slate-500 mt-0.5">Deleted files & hex viewer</p>
                </div>
              </button>

              <button
                onClick={() => setActiveTab("timeline")}
                className="p-4 bg-background border border-borderDark hover:border-brand-500/50 rounded-lg flex items-center gap-3 transition text-left group"
              >
                <div className="p-2 bg-brand-500/10 text-brand-500 rounded group-hover:bg-brand-500 group-hover:text-white transition">
                  <Clock className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-white">Super Timeline</h4>
                  <p className="text-xs text-slate-500 mt-0.5">Correlated event history</p>
                </div>
              </button>

              <button
                onClick={() => setActiveTab("alerts")}
                className="p-4 bg-background border border-borderDark hover:border-brand-500/50 rounded-lg flex items-center gap-3 transition text-left group"
              >
                <div className="p-2 bg-severity-critical/10 text-severity-critical rounded group-hover:bg-severity-critical group-hover:text-white transition">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-white">Triage Alerts</h4>
                  <p className="text-xs text-slate-500 mt-0.5">Execution & injection risks</p>
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderIngestionWizard = () => {
    return (
      <div className="flex-1 p-8 overflow-y-auto max-w-4xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Evidence Ingestion Pipeline</h1>
          <p className="text-slate-400 mt-1">Load file targets and trigger forensic correlation analysis</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          <div className="bg-panel border border-borderDark rounded-lg p-6 lg:col-span-2">
            <form onSubmit={handleIngestEvidence} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Evidence Label
                </label>
                <input
                  type="text"
                  required
                  value={ingestionName}
                  onChange={(e) => setIngestionName(e.target.value)}
                  placeholder="e.g. Memory Dump 001 - Host-XYZ"
                  className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Evidence Ingestion Target
                  </label>
                  <select
                    value={ingestionType}
                    onChange={(e) => setIngestionType(e.target.value as any)}
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500"
                  >
                    <option value="memory">Memory Image (Volatility 3)</option>
                    <option value="disk">Disk Image (pytsk3 / SleuthKit)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Execution Profile Mode
                  </label>
                  <select
                    value={ingestionMode}
                    onChange={(e) => setIngestionMode(e.target.value as any)}
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500"
                  >
                    <option value="simulation">Demonstration Simulation Mode</option>
                    <option value="live">Live Parsing Mode (Host Python)</option>
                  </select>
                </div>
              </div>

              {ingestionType === "memory" ? (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Memory Absolute File Path (on Server)
                  </label>
                  <input
                    type="text"
                    required
                    value={memoryFilePath}
                    onChange={(e) => setMemoryFilePath(e.target.value)}
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500 font-mono"
                  />
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Disk Image Absolute File Path (on Server)
                  </label>
                  <input
                    type="text"
                    required
                    value={diskFilePath}
                    onChange={(e) => setDiskFilePath(e.target.value)}
                    className="w-full bg-background border border-borderDark rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-brand-500 font-mono"
                  />
                </div>
              )}

              <div className="flex justify-end pt-4">
                <button
                  type="submit"
                  disabled={isIngesting}
                  className="px-6 py-2.5 bg-brand-500 hover:bg-brand-600 disabled:bg-slate-700 disabled:text-slate-400 rounded text-sm font-semibold tracking-wide transition flex items-center gap-2"
                >
                  {isIngesting ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-white"></div>
                      Executing Parser Job...
                    </>
                  ) : (
                    "Trigger File Ingestion"
                  )}
                </button>
              </div>
            </form>
          </div>

          <div className="bg-panel border border-borderDark rounded-lg p-6 lg:col-span-1 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">Execution Instructions</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              <strong>Demonstration Simulation Mode</strong> parses our pre-provided memory image and disk image to load a complete malware-triage sample case (including RunKeys registry persistence, network connections, fileless shellcode, and timeline logs).
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              <strong>Live Parsing Mode</strong> executes the Volatility 3 and pytsk3 engines dynamically over the supplied paths on this host. Large images can take minutes to complete scanning.
            </p>
          </div>
        </div>

        {/* Logs terminal box */}
        {ingestionLogs && (
          <div className="bg-black border border-borderDark rounded p-4 font-mono text-xs text-emerald-400 space-y-2 max-h-72 overflow-y-auto whitespace-pre-wrap shadow-inner">
            <div className="text-slate-400 font-bold border-b border-borderDark pb-2 flex justify-between">
              <span>PIP JOB LOG TERMINAL</span>
              <span className="text-brand-500 animate-pulse">● LIVE CONNECTION</span>
            </div>
            {ingestionLogs}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      {selectedCase && (
        <aside className="w-64 bg-panel border-r border-borderDark flex flex-col justify-between select-none">
          <div className="p-5 flex flex-col space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-brand-500 flex items-center justify-center font-bold text-white text-base">FC</div>
              <div>
                <h2 className="text-sm font-semibold tracking-wider uppercase text-white">ForensiCore XDR</h2>
                <span className="text-[10px] text-brand-500 font-semibold tracking-widest font-mono uppercase">Workstation</span>
              </div>
            </div>

            <div className="pt-4 space-y-1">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest px-3 mb-2 font-mono">Case Engine</p>
              <button
                onClick={() => setActiveTab("dashboard")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "dashboard" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <TrendingUp className="w-4 h-4" /> Case Dashboard
              </button>
              <button
                onClick={() => setActiveTab("ingest")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "ingest" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <UploadCloud className="w-4 h-4" /> Ingest Evidence
              </button>

              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest px-3 my-3 pt-3 border-t border-borderDark/40 font-mono">Triage Explorers</p>
              <button
                onClick={() => setActiveTab("processes")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "processes" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <Cpu className="w-4 h-4" /> Process Tree
              </button>
              <button
                onClick={() => setActiveTab("filesystem")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "filesystem" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <FolderOpen className="w-4 h-4" /> Filesystem
              </button>
              <button
                onClick={() => setActiveTab("timeline")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "timeline" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <Clock className="w-4 h-4" /> Super Timeline
              </button>
              <button
                onClick={() => setActiveTab("registry")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "registry" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <Database className="w-4 h-4" /> Registry & Persistence
              </button>
              <button
                onClick={() => setActiveTab("alerts")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "alerts" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <ShieldAlert className="w-4 h-4" /> Triage Alerts
              </button>

              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest px-3 my-3 pt-3 border-t border-borderDark/40 font-mono">Detections & Rules</p>
              <button
                onClick={() => setActiveTab("yara")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "yara" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <FileCode2 className="w-4 h-4" /> YARA Rules Lab
              </button>
              <button
                onClick={() => setActiveTab("notes")}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition font-medium ${activeTab === "notes" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <FileText className="w-4 h-4" /> Notes & Reports
              </button>
            </div>
          </div>

          {/* User profile / Log out */}
          <div className="p-4 border-t border-borderDark/60 flex items-center justify-between text-slate-400 bg-background/30 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-slate-800 flex items-center justify-center font-bold text-white text-xs border border-borderDark"><User className="w-3.5 h-3.5" /></div>
              <div>
                <p className="font-semibold text-slate-200 line-clamp-1">Investigator</p>
                <span className="text-[10px]">Tier 3 Analyst</span>
              </div>
            </div>
            <button
              onClick={() => setSelectedCase(null)}
              className="p-1 hover:text-white rounded hover:bg-slate-800 transition"
              title="Close Case"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </aside>
      )}

      {/* Main Content Pane */}
      <main className="flex-1 flex flex-col min-w-0 bg-background relative overflow-hidden">
        {selectedCase && (
          <header className="bg-panel border-b border-borderDark px-8 py-3.5 flex items-center justify-between z-10">
            <div className="flex items-center gap-2.5 text-sm text-slate-300">
              <span className="text-slate-500">Case Locker:</span>
              <span className="font-semibold text-white px-2 py-0.5 rounded bg-brand-500/10 border border-brand-500/20">{selectedCase.name}</span>
            </div>
            <button
              onClick={() => setSelectedCase(null)}
              className="text-xs px-3 py-1.5 border border-borderDark hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded font-semibold transition"
            >
              Back to Cases Locker
            </button>
          </header>
        )}
        {renderContent()}
      </main>
    </div>
  );
}
