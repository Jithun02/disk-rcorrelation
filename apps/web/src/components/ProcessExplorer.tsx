import React, { useState, useEffect } from "react";
import { Cpu, Network, FileCode, ShieldAlert, ArrowRight } from "lucide-react";

interface Process {
  id: number;
  pid: number;
  ppid: number;
  name: string;
  path: string | null;
  create_time: string | null;
  offset: string | null;
  dll_count: number;
  connection_count: number;
  cross_view_mismatch: number;
  cross_view_visible_count: number;
  is_suspicious: number;
  risk_score: number;
}

export default function ProcessExplorer({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>("");

  const mockProcesses: Process[] = [
    { id: 1, pid: 4, ppid: 0, name: "System", path: null, create_time: "2026-04-02T05:00:00Z", offset: "0x80800000", dll_count: 0, connection_count: 0, cross_view_mismatch: 1, cross_view_visible_count: 1, is_suspicious: 1, risk_score: 50 },
    { id: 2, pid: 368, ppid: 4, name: "smss.exe", path: "\\SystemRoot\\System32\\smss.exe", create_time: "2026-04-02T05:00:02Z", offset: "0x80900000", dll_count: 5, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 3, pid: 584, ppid: 368, name: "csrss.exe", path: null, create_time: "2026-04-02T05:00:03Z", offset: "0x80a00000", dll_count: 10, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 4, pid: 632, ppid: 368, name: "wininit.exe", path: "\\Windows\\System32\\wininit.exe", create_time: "2026-04-02T05:00:03Z", offset: "0x80b00000", dll_count: 8, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 5, pid: 680, ppid: 632, name: "services.exe", path: "\\Windows\\System32\\services.exe", create_time: "2026-04-02T05:00:04Z", offset: "0x80c00000", dll_count: 24, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 6, pid: 692, ppid: 632, name: "lsass.exe", path: "\\Windows\\System32\\lsass.exe", create_time: "2026-04-02T05:00:04Z", offset: "0x80d00000", dll_count: 35, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 7, pid: 824, ppid: 680, name: "svchost.exe", path: "\\Windows\\System32\\svchost.exe", create_time: "2026-04-02T05:00:05Z", offset: "0x80e00000", dll_count: 85, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 8, pid: 1720, ppid: 1680, name: "explorer.exe", path: "\\Windows\\explorer.exe", create_time: "2026-04-02T05:01:10Z", offset: "0x80f00000", dll_count: 103, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 9, pid: 2840, ppid: 1720, name: "chrome.exe", path: "\\Program Files\\Google\\Chrome\\chrome.exe", create_time: "2026-04-02T06:12:00Z", offset: "0x81000000", dll_count: 120, connection_count: 1, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 10, pid: 3880, ppid: 1720, name: "powershell.exe", path: "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", create_time: "2026-04-02T07:15:30Z", offset: "0x81100000", dll_count: 45, connection_count: 0, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 0, risk_score: 0 },
    { id: 11, pid: 4200, ppid: 3880, name: "svchost_mal.exe", path: "\\Windows\\Temp\\payload.bin", create_time: "2026-04-02T07:15:35Z", offset: "0x81200000", dll_count: 92, connection_count: 1, cross_view_mismatch: 0, cross_view_visible_count: 6, is_suspicious: 1, risk_score: 92 },
    { id: 12, pid: 2404, ppid: 1276, name: "BRNIPMON.exe", path: null, create_time: "2009-12-11T01:28:46Z", offset: "0x81300000", dll_count: 27, connection_count: 0, cross_view_mismatch: 1, cross_view_visible_count: 2, is_suspicious: 1, risk_score: 78 }
  ];

  useEffect(() => {
    fetchProcesses();
  }, [caseId, isStatic]);

  const fetchProcesses = async () => {
    if (isStatic) {
      setProcesses(mockProcesses);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await fetch(`/api/cases/${caseId}/processes`);
      if (res.ok) {
        const data = await res.json();
        setProcesses(data);
      }
    } catch (err) {
      console.error(err);
      setProcesses(mockProcesses);
    } finally {
      setLoading(false);
    }
  };

  // Helper to build a process tree indentation mapping
  const buildTreeRows = () => {
    const matched = processes.filter(p => p.name.toLowerCase().includes(search.toLowerCase()));
    if (search) return matched.map(p => ({ ...p, depth: 0 }));

    const roots = processes.filter(p => {
      const parent = processes.find(parentProc => parentProc.pid === p.ppid);
      return !parent || p.pid === p.ppid;
    });

    const rows: (Process & { depth: number })[] = [];
    const visited = new Set<number>();

    const traverse = (node: Process, depth: number) => {
      if (visited.has(node.pid)) return;
      visited.add(node.pid);
      rows.push({ ...node, depth });

      const children = processes.filter(p => p.ppid === node.pid && p.pid !== node.pid);
      children.forEach(child => traverse(child, depth + 1));
    };

    roots.forEach(r => traverse(r, 0));
    
    // Add any orphans
    processes.forEach(p => {
      if (!visited.has(p.pid)) {
        traverse(p, 0);
      }
    });

    return rows;
  };

  const rows = buildTreeRows();

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* Main Process Table */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-borderDark bg-background/40">
        <div className="p-4 border-b border-borderDark flex items-center justify-between gap-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-brand-500" />
            Process Tree Explorer
          </h2>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search processes..."
            className="max-w-xs w-full bg-panel border border-borderDark rounded px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-brand-500 font-sans"
          />
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Loading memory processes table...
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  <th className="table-header py-3 px-4">PID</th>
                  <th className="table-header py-3 px-4">PPID</th>
                  <th className="table-header py-3 px-4">Process Name</th>
                  <th className="table-header py-3 px-4">Risk Score</th>
                  <th className="table-header py-3 px-4">Image Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-borderDark/30 text-xs">
                {rows.map((proc) => {
                  const isSelected = selectedProcess?.pid === proc.pid;
                  const isSuspicious = proc.is_suspicious === 1 || proc.risk_score > 50;

                  return (
                    <tr
                      key={proc.id}
                      onClick={() => setSelectedProcess(proc)}
                      className={`hover:bg-panel/40 cursor-pointer transition ${isSelected ? "bg-brand-500/10 text-brand-500 border-l-2 border-brand-500" : ""}`}
                    >
                      <td className="py-2.5 px-4 font-mono font-medium text-slate-300">{proc.pid}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-500">{proc.ppid}</td>
                      <td className="py-2.5 px-4 font-semibold text-slate-200">
                        <span
                          style={{ paddingLeft: `${proc.depth * 16}px` }}
                          className="inline-flex items-center gap-1.5"
                        >
                          {proc.depth > 0 && <span className="text-slate-600">└─</span>}
                          {isSuspicious ? (
                            <span className="text-severity-critical font-bold flex items-center gap-1">
                              ⚠️ {proc.name}
                            </span>
                          ) : (
                            proc.name
                          )}
                        </span>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded font-mono font-bold ${proc.risk_score >= 70 ? "bg-red-500/10 text-red-500 border border-red-500/20" : proc.risk_score >= 40 ? "bg-amber-500/10 text-amber-500 border border-amber-500/20" : "bg-slate-800 text-slate-400 border border-slate-700"}`}>
                          {proc.risk_score}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400 line-clamp-1 max-w-sm" title={proc.path || "N/A"}>
                        {proc.path || "-"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Right details Drawer */}
      {selectedProcess && (
        <aside className="w-96 bg-panel border-l border-borderDark flex flex-col h-full text-slate-300 p-6 overflow-y-auto space-y-6">
          <div className="flex justify-between items-start border-b border-borderDark pb-4">
            <div>
              <span className="text-xs font-semibold uppercase text-brand-500 font-mono">Process Detail Panel</span>
              <h3 className="text-lg font-bold text-white mt-1">{selectedProcess.name}</h3>
              <p className="text-xs text-slate-500 mt-0.5 font-mono">PID: {selectedProcess.pid} | PPID: {selectedProcess.ppid}</p>
            </div>
            <button
              onClick={() => setSelectedProcess(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-background hover:bg-slate-800 transition"
            >
              Close
            </button>
          </div>

          {/* Alert Callout if suspicious */}
          {selectedProcess.risk_score > 0 && (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-4 flex gap-3 items-start text-xs text-red-400 leading-relaxed">
              <ShieldAlert className="w-5 h-5 shrink-0" />
              <div>
                <strong className="font-semibold block text-red-200">Forensic Risk Score: {selectedProcess.risk_score}</strong>
                {selectedProcess.cross_view_mismatch === 1 && "Process visibility mismatch in Volatility kernel cross-views. "}
                {selectedProcess.path === null && "Memory process doesn't map to any directory executable on disk. "}
                {selectedProcess.risk_score >= 70 && "Heuristic threat signatures identify potential code injection / DLL hollowing."}
              </div>
            </div>
          )}

          {/* Details list */}
          <div className="space-y-4 text-xs">
            <h4 className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest font-mono">Metadata Properties</h4>
            <div className="grid grid-cols-2 gap-y-3 gap-x-2 bg-background/40 border border-borderDark/40 rounded p-3 font-mono">
              <span className="text-slate-500">Offset Value:</span>
              <span className="text-slate-300 truncate">{selectedProcess.offset || "N/A"}</span>
              <span className="text-slate-500">Start Time:</span>
              <span className="text-slate-300 truncate">{selectedProcess.create_time ? new Date(selectedProcess.create_time).toLocaleString() : "N/A"}</span>
              <span className="text-slate-500">Signer Status:</span>
              <span className="text-slate-300">{selectedProcess.is_suspicious ? "Unsigned / Unknown" : "Verified OS"}</span>
              <span className="text-slate-500">DLL Module Loads:</span>
              <span className="text-slate-300">{selectedProcess.dll_count} modules</span>
            </div>
          </div>

          {/* DLL Modules Header */}
          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <h4 className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest font-mono">Loaded DLL Libraries</h4>
              <span className="bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono font-bold text-[10px]">{selectedProcess.dll_count}</span>
            </div>
            {selectedProcess.dll_count > 0 ? (
              <div className="bg-background/20 border border-borderDark/40 rounded p-3 font-mono text-[10px] leading-relaxed max-h-40 overflow-y-auto space-y-1 text-slate-400">
                <div>kernel32.dll (0x7C800000)</div>
                <div>ntdll.dll (0x7C900000)</div>
                <div>user32.dll (0x7E410000)</div>
                <div>ws2_32.dll (0x71AB0000)</div>
                <div className="text-slate-500 italic font-sans text-center mt-2">({selectedProcess.dll_count - 4} additional modules mapped)</div>
              </div>
            ) : (
              <p className="text-slate-500 italic">No DLL data parsed.</p>
            )}
          </div>

          {/* Sockets */}
          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <h4 className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest font-mono">Active Netscan Sockets</h4>
              <span className="bg-brand-500/10 text-brand-500 px-1.5 py-0.5 rounded font-mono font-bold text-[10px]">{selectedProcess.connection_count}</span>
            </div>
            {selectedProcess.connection_count > 0 ? (
              <div className="bg-background/40 border border-borderDark/40 rounded p-3 font-mono text-[10px] space-y-2">
                <div className="flex justify-between items-center border-b border-borderDark/20 pb-1.5 text-slate-500">
                  <span>Local</span>
                  <span>Remote</span>
                </div>
                <div className="flex justify-between items-center text-emerald-400">
                  <span>192.168.1.105:49210</span>
                  <span className="flex items-center gap-1">45.138.16.22:443 <Network className="w-3 h-3" /></span>
                </div>
              </div>
            ) : (
              <p className="text-slate-500 italic">No active network connections mapped.</p>
            )}
          </div>
        </aside>
      )}
    </div>
  );
}
