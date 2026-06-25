import React, { useState, useEffect } from "react";
import { ShieldAlert, AlertTriangle, Info, Terminal, CheckCircle2 } from "lucide-react";

interface Alert {
  id: number;
  type: string;
  severity: string;
  score: number;
  process: string | null;
  pid: number | null;
  path: string | null;
  reason: string | null;
  details: string | null;
}

export default function TriageAlerts({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const mockAlerts: Alert[] = [
    {
      id: 1,
      type: "fileless_malware_candidate",
      severity: "critical",
      score: 92,
      process: "svchost_mal.exe",
      pid: 4200,
      path: "C:\\Windows\\Temp\\payload.bin",
      reason: "Process running out of temp directory with missing on-disk matching executable.",
      details: "The image path points to C:\\Windows\\Temp\\payload.bin, which behaves like a fileless/injected shellcode. It was spawned by powershell.exe."
    },
    {
      id: 2,
      type: "hidden_process_psxview_mismatch",
      severity: "high",
      score: 78,
      process: "BRNIPMON.exe",
      pid: 2404,
      path: null,
      reason: "Process has inconsistent visibility in psxview checks.",
      details: "{\"pslist\":true,\"psscan\":false,\"thrdproc\":false,\"csrss\":true,\"session\":false,\"deskthrd\":false}"
    },
    {
      id: 3,
      type: "suspicious_process_name",
      severity: "medium",
      score: 45,
      process: "svchost_mal.exe",
      pid: 4200,
      path: "C:\\Windows\\Temp\\payload.bin",
      reason: "Process name mimicks system process svchost.exe.",
      details: "svchost_mal.exe has an extra suffix '_mal' to mislead defenders and resides in Windows Temp instead of System32."
    }
  ];

  useEffect(() => {
    fetchAlerts();
  }, [caseId, isStatic]);

  const fetchAlerts = async () => {
    if (isStatic) {
      setAlerts(mockAlerts);
      setSelectedAlert(mockAlerts[0] || null);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await fetch(`/api/cases/${caseId}/alerts`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
        if (data.length > 0) {
          setSelectedAlert(data[0]);
        }
      }
    } catch (err) {
      console.error(err);
      setAlerts(mockAlerts);
      setSelectedAlert(mockAlerts[0] || null);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "text-red-500 border-red-500/30 bg-red-500/10";
      case "high": return "text-orange-500 border-orange-500/30 bg-orange-500/10";
      case "medium": return "text-yellow-500 border-yellow-500/30 bg-yellow-500/10";
      default: return "text-emerald-500 border-emerald-500/30 bg-emerald-500/10";
    }
  };

  const getSeverityIcon = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return <ShieldAlert className="w-4 h-4 shrink-0 text-red-500" />;
      case "high": return <AlertTriangle className="w-4 h-4 shrink-0 text-orange-500" />;
      case "medium": return <AlertTriangle className="w-4 h-4 shrink-0 text-yellow-500" />;
      default: return <Info className="w-4 h-4 shrink-0 text-emerald-500" />;
    }
  };

  const getDetectionsSummary = () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(a => {
      const s = a.severity.toLowerCase();
      if (s in counts) counts[s as keyof typeof counts]++;
      else counts.low++;
    });
    return counts;
  };

  const summary = getDetectionsSummary();

  const getRecommendedAction = (alertType: string) => {
    switch (alertType) {
      case "fileless_malware_candidate":
        return [
          "Perform RAM hollowed process dump using Volatility vadinfo/vaddump plugins.",
          "Identify active C2 sockets associated with this PID in the Network Explorer.",
          "Inspect memory heap string captures for raw IP/Domain credentials."
        ];
      case "process_injection_candidate":
        return [
          "Dump matching executable sections from memory using Volatility dlldump.",
          "Verify the executable image signature against OS catalog files.",
          "Cross-reference loaded DLL bases for hollowed/unmapped DLL instances."
        ];
      case "hidden_process_psxview_mismatch":
      case "hidden_process_psscan_only":
        return [
          "This indicates kernel rootkit hook manipulation of the ActiveProcessLinks double-linked list.",
          "Perform driver/SSDTHook scan using Volatility ssdt or modules plugins.",
          "Quarantine host endpoint immediately to halt potential lateral movements."
        ];
      case "cross_view_process_mismatch":
        return [
          "Correlate handle table outputs against the thread listings using Volatility handles/threads plugins.",
          "Dump memory pages containing execution markers."
        ];
      default:
        return [
          "Inspect associated timestamps (MACB) in Filesystem Explorer.",
          "Extract file hashes and query threat reputation engines (e.g. VirusTotal).",
          "Log notes explaining anomaly indicators."
        ];
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* Alert Lists */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-borderDark bg-background/40">
        <div className="p-4 border-b border-borderDark flex items-center justify-between bg-panel/30">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-brand-500" />
            Triage Detection Alerts
          </h2>
          {/* Summary Chips */}
          <div className="flex gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-500 border border-red-500/20 font-mono">
              CRITICAL: {summary.critical}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/10 text-orange-500 border border-orange-500/20 font-mono">
              HIGH: {summary.high}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/10 text-yellow-500 border border-yellow-500/20 font-mono">
              MED: {summary.medium}
            </span>
          </div>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Correlating alerts database rules...
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 text-sm italic">
            Zero threat indicators detected over this case locker.
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {alerts.map((a) => {
              const isSelected = selectedAlert?.id === a.id;
              return (
                <div
                  key={a.id}
                  onClick={() => setSelectedAlert(a)}
                  className={`p-4 border rounded-lg cursor-pointer transition flex justify-between items-start ${isSelected ? "bg-panel border-brand-500 shadow-md shadow-brand-500/5" : "bg-panel/40 border-borderDark/60 hover:bg-panel/70"}`}
                >
                  <div className="flex gap-3 items-start">
                    {getSeverityIcon(a.severity)}
                    <div className="space-y-1">
                      <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                        {a.type.replace(/_/g, " ").toUpperCase()}
                        <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase border ${getSeverityColor(a.severity)}`}>
                          {a.severity}
                        </span>
                      </h4>
                      <p className="text-xs text-slate-400 leading-normal">{a.reason}</p>
                      <div className="flex gap-3 text-[10px] text-slate-500 font-mono pt-1">
                        {a.process && <span>Process: <strong className="text-slate-300 font-medium">{a.process}</strong></span>}
                        {a.pid && <span>PID: <strong className="text-slate-300 font-medium">{a.pid}</strong></span>}
                      </div>
                    </div>
                  </div>
                  <div className="font-mono text-sm font-bold bg-background border border-borderDark px-2 py-1 rounded text-slate-300">
                    {a.score}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Explanation drawer */}
      {selectedAlert && (
        <aside className="w-[450px] bg-panel border-l border-borderDark flex flex-col h-full text-slate-300 p-6 overflow-y-auto space-y-6">
          <div className="border-b border-borderDark pb-4">
            <span className="text-xs font-semibold uppercase text-brand-500 font-mono">SOC Explanation Panel</span>
            <h3 className="text-base font-bold text-white mt-1 break-words">
              {selectedAlert.type.replace(/_/g, " ").toUpperCase()}
            </h3>
            <p className="text-xs text-slate-500 mt-1 font-mono">Risk score mapping weight: {selectedAlert.score}/100</p>
          </div>

          {/* Explainable detail */}
          <div className="space-y-4 text-xs leading-relaxed">
            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1.5">Anomaly Summary</h4>
              <p className="bg-background border border-borderDark/40 rounded p-3 text-slate-200">
                {selectedAlert.reason}
              </p>
            </div>

            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1.5">Supporting Artifacts</h4>
              <div className="bg-background border border-borderDark/40 rounded p-3 font-mono text-[10px] space-y-1.5">
                <div className="flex justify-between"><span className="text-slate-500">Process Object:</span><span className="text-slate-300 font-medium">{selectedAlert.process || "N/A"}</span></div>
                <div className="flex justify-between"><span className="text-slate-500">Process PID:</span><span className="text-slate-300 font-medium">{selectedAlert.pid || "N/A"}</span></div>
                {selectedAlert.path && (
                  <div className="flex justify-between"><span className="text-slate-500">Image Path:</span><span className="text-slate-300 font-medium truncate max-w-[200px]" title={selectedAlert.path}>{selectedAlert.path}</span></div>
                )}
              </div>
            </div>

            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1.5">Rule Explanation Heuristics</h4>
              <div className="bg-black/40 border border-borderDark/40 rounded p-3 font-sans text-slate-300 space-y-2">
                <p>
                  {selectedAlert.type === "fileless_malware_candidate" && "A memory thread was found running code in a page mapped to raw DLL pools without a valid image signature files backing it up on disk, representing high-probability process execution hijack."}
                  {selectedAlert.type === "hidden_process_psxview_mismatch" && "The volatility psxview plugin cross-references active process structures in memory. A mismatch signifies manual thread alterations typical in kernel-level process hiding malware."}
                  {selectedAlert.type === "process_injection_candidate" && "The thread execution parameters exhibit a highly suspicious load frequency of DLL libraries combined with active socket networks, matching standard DLL hollowing patterns."}
                  {selectedAlert.type === "suspicious_process_name" && "The image filename utilizes character variations designed to deceive security analysts and match standard administrative tools (e.g. svchost_mal.exe)."}
                  {selectedAlert.type === "suspicious_execution_path" && "The process image executes out of high-risk directories (e.g. C:\\Windows\\Temp, AppData\\Local\\Temp) which are generally writable by user privileges."}
                  {!["fileless_malware_candidate", "hidden_process_psxview_mismatch", "process_injection_candidate", "suspicious_process_name", "suspicious_execution_path"].includes(selectedAlert.type) && "The correlated configuration states mismatch indicators mapping directly to malicious thread profiles."}
                </p>
              </div>
            </div>

            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-2">Recommended Investigator Playbook</h4>
              <div className="space-y-2">
                {getRecommendedAction(selectedAlert.type).map((act, idx) => (
                  <div key={idx} className="flex gap-2.5 items-start text-slate-300 bg-background/25 border border-borderDark/30 p-2.5 rounded">
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-brand-500 mt-0.5" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}
