import React, { useState, useEffect } from "react";
import { Database, ShieldAlert, Key, Globe, LayoutList, History } from "lucide-react";

interface RegistryEntry {
  id: number;
  hive: string;
  key_path: string;
  value_name: string;
  value_data: string;
  last_written: string | null;
}

interface PersistenceItem {
  id: number;
  type: string;
  name: string;
  target_path: string | null;
  command_line: string | null;
  score: number;
}

interface BrowserLog {
  id: number;
  browser: string;
  type: string;
  url: string | null;
  title: string | null;
  timestamp: string | null;
  download_path: string | null;
  file_size: number | null;
}

export default function RegistryPersistence({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [subTab, setSubTab] = useState<"persistence" | "registry" | "browser">("persistence");
  const [registryEntries, setRegistryEntries] = useState<RegistryEntry[]>([]);
  const [persistenceItems, setPersistenceItems] = useState<PersistenceItem[]>([]);
  const [browserActivity, setBrowserActivity] = useState<BrowserLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const mockRegistry: RegistryEntry[] = [
    { id: 1, hive: "HKLM", key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", value_name: "SecurityHealth", value_data: "C:\\Windows\\Temp\\payload.bin", last_written: "2026-04-02T07:15:40Z" },
    { id: 2, hive: "HKLM", key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", value_name: "OneDrive", value_data: "C:\\Windows\\System32\\OneDrive.exe", last_written: "2026-04-01T10:00:00Z" },
    { id: 3, hive: "HKLM", key_path: "System\\CurrentControlSet\\Services\\mal_service", value_name: "ImagePath", value_data: "C:\\Windows\\Temp\\payload.bin", last_written: "2026-04-02T07:15:42Z" }
  ];

  const mockPersistence: PersistenceItem[] = [
    { id: 1, type: "RunKey", name: "SecurityHealth", target_path: "/Windows/Temp/payload.bin", command_line: "C:\\Windows\\Temp\\payload.bin", score: 90 },
    { id: 2, type: "Service", name: "mal_service", target_path: "/Windows/Temp/payload.bin", command_line: "C:\\Windows\\Temp\\payload.bin", score: 85 },
    { id: 3, type: "ScheduledTask", name: "UpdateChecker", target_path: "/Windows/System32/cmd.exe", command_line: "cmd.exe /c start C:\\Windows\\Temp\\payload.bin", score: 75 }
  ];

  const mockBrowser: BrowserLog[] = [
    { id: 1, browser: "Chrome", type: "history", url: "https://malicious-site.com/downloads/invoice_pdf.exe", title: "Invoice Document PDF Download", timestamp: "2026-04-02T06:12:12Z", download_path: null, file_size: null },
    { id: 2, browser: "Chrome", type: "download", url: "https://malicious-site.com/downloads/invoice_pdf.exe", title: null, timestamp: "2026-04-02T06:12:45Z", download_path: "/Users/Administrator/Downloads/invoice_pdf.exe", file_size: 182300 }
  ];

  useEffect(() => {
    fetchData();
  }, [caseId, isStatic]);

  const fetchData = async () => {
    if (isStatic) {
      setRegistryEntries(mockRegistry);
      setPersistenceItems(mockPersistence);
      setBrowserActivity(mockBrowser);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const regRes = await fetch(`/api/cases/${caseId}/registry`);
      if (regRes.ok) {
        const regData = await regRes.json();
        setRegistryEntries(regData.entries || []);
        setPersistenceItems(regData.persistence || []);
      }

      const browRes = await fetch(`/api/cases/${caseId}/browser`);
      if (browRes.ok) {
        const browData = await browRes.json();
        setBrowserActivity(browData || []);
      }
    } catch (err) {
      console.error(err);
      setRegistryEntries(mockRegistry);
      setPersistenceItems(mockPersistence);
      setBrowserActivity(mockBrowser);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-background/40">
      {/* Tab bar header */}
      <div className="p-4 border-b border-borderDark flex flex-wrap items-center justify-between gap-4 bg-panel/30">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Database className="w-5 h-5 text-brand-500" />
          Registry & Persistence Explorer
        </h2>

        <div className="flex bg-background border border-borderDark rounded p-0.5">
          <button
            onClick={() => setSubTab("persistence")}
            className={`px-3 py-1 text-xs rounded font-medium transition ${subTab === "persistence" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200"}`}
          >
            Persistence Points
          </button>
          <button
            onClick={() => setSubTab("registry")}
            className={`px-3 py-1 text-xs rounded font-medium transition ${subTab === "registry" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200"}`}
          >
            AutoRun Keys
          </button>
          <button
            onClick={() => setSubTab("browser")}
            className={`px-3 py-1 text-xs rounded font-medium transition ${subTab === "browser" ? "bg-brand-500 text-white" : "text-slate-400 hover:text-slate-200"}`}
          >
            Browser Activity
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
          Extracting and correlating system settings...
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto p-6">
          {subTab === "persistence" && (
            <div className="space-y-6">
              <div className="border border-borderDark rounded-lg overflow-hidden bg-panel/10">
                <div className="p-4 bg-panel/30 border-b border-borderDark flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-severity-high" />
                  <h3 className="text-sm font-semibold text-white">Active Persistence Detections</h3>
                </div>
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr>
                      <th className="table-header py-2.5 px-4">Type</th>
                      <th className="table-header py-2.5 px-4">Name</th>
                      <th className="table-header py-2.5 px-4">Command / Target Payload</th>
                      <th className="table-header py-2.5 px-4">Risk Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-borderDark/20 font-sans">
                    {persistenceItems.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-4 text-center text-slate-500 italic">No persistent programs installed.</td>
                      </tr>
                    ) : (
                      persistenceItems.map(item => (
                        <tr key={item.id} className="hover:bg-panel/20 transition text-slate-300">
                          <td className="py-3 px-4 font-mono font-medium">{item.type}</td>
                          <td className="py-3 px-4 font-semibold text-slate-200">{item.name}</td>
                          <td className="py-3 px-4 font-mono text-slate-400 max-w-lg truncate" title={item.command_line || item.target_path || ""}>
                            <code>{item.command_line || item.target_path}</code>
                          </td>
                          <td className="py-3 px-4 font-mono">
                            <span className={`px-2 py-0.5 rounded font-bold ${item.score >= 75 ? "bg-red-500/10 text-red-500" : "bg-amber-500/10 text-amber-500"}`}>
                              {item.score}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {subTab === "registry" && (
            <div className="border border-borderDark rounded-lg overflow-hidden bg-panel/10">
              <div className="p-4 bg-panel/30 border-b border-borderDark flex items-center gap-2">
                <Key className="w-4 h-4 text-brand-500" />
                <h3 className="text-sm font-semibold text-white">Registry Hive Keys</h3>
              </div>
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr>
                    <th className="table-header py-2.5 px-4">Hive</th>
                    <th className="table-header py-2.5 px-4">Key Path</th>
                    <th className="table-header py-2.5 px-4">Value Name</th>
                    <th className="table-header py-2.5 px-4">Value Data</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-borderDark/20 font-mono text-slate-400">
                  {registryEntries.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-4 text-center text-slate-500 italic font-sans">No registry keys parsed.</td>
                    </tr>
                  ) : (
                    registryEntries.map(entry => (
                      <tr key={entry.id} className="hover:bg-panel/20 transition">
                        <td className="py-3 px-4 text-slate-300 font-semibold">{entry.hive}</td>
                        <td className="py-3 px-4 truncate max-w-xs text-slate-300" title={entry.key_path}>{entry.key_path}</td>
                        <td className="py-3 px-4 text-brand-500 font-semibold">{entry.value_name}</td>
                        <td className="py-3 px-4 text-slate-200 truncate max-w-sm" title={entry.value_data}><code>{entry.value_data}</code></td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {subTab === "browser" && (
            <div className="border border-borderDark rounded-lg overflow-hidden bg-panel/10">
              <div className="p-4 bg-panel/30 border-b border-borderDark flex items-center gap-2">
                <Globe className="w-4 h-4 text-emerald-500" />
                <h3 className="text-sm font-semibold text-white">Web Browser Downloads & Histories</h3>
              </div>
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr>
                    <th className="table-header py-2.5 px-4">Browser</th>
                    <th className="table-header py-2.5 px-4">Type</th>
                    <th className="table-header py-2.5 px-4">URL / Origin</th>
                    <th className="table-header py-2.5 px-4">Download Destination / Title</th>
                    <th className="table-header py-2.5 px-4">Timestamp (UTC)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-borderDark/20 text-slate-300 font-sans">
                  {browserActivity.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-slate-500 italic">No browser database logs extracted.</td>
                    </tr>
                  ) : (
                    browserActivity.map(act => (
                      <tr key={act.id} className="hover:bg-panel/20 transition">
                        <td className="py-3 px-4 font-semibold text-slate-200">{act.browser}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[9px] uppercase tracking-wide ${act.type === "download" ? "bg-red-500/10 text-red-500" : "bg-emerald-500/10 text-emerald-500"}`}>
                            {act.type}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 max-w-xs truncate" title={act.url || ""}>{act.url}</td>
                        <td className="py-3 px-4 truncate max-w-xs" title={act.download_path || act.title || ""}>
                          {act.type === "download" ? (
                            <code className="text-amber-500 font-mono text-[10px]">{act.download_path}</code>
                          ) : (
                            <span className="text-slate-300">{act.title || "-"}</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{act.timestamp ? new Date(act.timestamp).toUTCString() : "-"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
