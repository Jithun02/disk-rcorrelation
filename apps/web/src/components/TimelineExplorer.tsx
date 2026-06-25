import React, { useState, useEffect } from "react";
import { Clock, Filter, AlertTriangle, HelpCircle } from "lucide-react";

interface TimelineEvent {
  id: number;
  timestamp: string;
  event_type: string;
  details_json: string;
  severity: string;
  details: any;
}

export default function TimelineExplorer({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  
  // Filters
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [search, setSearch] = useState<string>("");

  const mockEvents: TimelineEvent[] = [
    { id: 1, timestamp: "2026-04-02T06:12:00Z", event_type: "process_start", severity: "low", details_json: "{}", details: { pid: 2840, name: "chrome.exe" } },
    { id: 2, timestamp: "2026-04-02T06:12:12Z", event_type: "browser_download", severity: "high", details_json: "{}", details: { browser: "Chrome", url: "https://malicious-site.com/downloads/invoice_pdf.exe", download_path: "/Users/Administrator/Downloads/invoice_pdf.exe" } },
    { id: 3, timestamp: "2026-04-02T06:12:45Z", event_type: "file_modified", severity: "high", details_json: "{}", details: { path: "/Users/Administrator/Downloads/invoice_pdf.exe", deleted: true } },
    { id: 4, timestamp: "2026-04-02T07:15:30Z", event_type: "process_start", severity: "low", details_json: "{}", details: { pid: 3880, name: "powershell.exe" } },
    { id: 5, timestamp: "2026-04-02T07:15:34Z", event_type: "file_modified", severity: "high", details_json: "{}", details: { path: "/Windows/Temp/payload.bin", deleted: false } },
    { id: 6, timestamp: "2026-04-02T07:15:35Z", event_type: "process_start", severity: "high", details_json: "{}", details: { pid: 4200, name: "svchost_mal.exe" } },
    { id: 7, timestamp: "2026-04-02T07:15:36Z", event_type: "network_connection", severity: "high", details_json: "{}", details: { pid: 4200, remote: "45.138.16.22:443" } }
  ];

  useEffect(() => {
    fetchTimeline();
  }, [caseId, typeFilter, severityFilter, isStatic]);

  const fetchTimeline = async () => {
    if (isStatic) {
      let filtered = [...mockEvents];
      if (typeFilter) {
        filtered = filtered.filter(f => f.event_type === typeFilter);
      }
      if (severityFilter) {
        filtered = filtered.filter(f => f.severity === severityFilter);
      }
      setEvents(filtered);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (typeFilter) params.append("type", typeFilter);
      if (severityFilter) params.append("severity", severityFilter);
      
      const res = await fetch(`/api/cases/${caseId}/timeline?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data);
      }
    } catch (err) {
      console.error(err);
      setEvents(mockEvents);
    } finally {
      setLoading(false);
    }
  };

  const filteredEvents = events.filter(evt => {
    if (!search) return true;
    const text = JSON.stringify(evt.details || {}).toLowerCase() + evt.event_type.toLowerCase();
    return text.includes(search.toLowerCase());
  });

  const getEventDescription = (evt: TimelineEvent) => {
    const d = evt.details || {};
    switch (evt.event_type) {
      case "process_start":
        return `Process Spawned: "${d.name}" (PID ${d.pid})`;
      case "file_modified":
        return `File Alteration: "${d.path}" ${d.deleted ? "(Deleted)" : "(Allocated)"}`;
      case "network_connection":
        return `Outbound network connection by PID ${d.pid} to ${d.remote}`;
      case "registry_modified":
        return `Registry Persistence Modified: [${d.hive}] ${d.key_path}\\${d.value_name} -> "${d.value_data}"`;
      case "browser_download":
        return `Web Browser Download: ${d.browser} downloaded URL: ${d.url} to path: "${d.download_path}"`;
      default:
        return d.reason || `Forensic event logs flagged: ${evt.event_type}`;
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* Event Timeline Table */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-borderDark bg-background/40">
        {/* Toolbar */}
        <div className="p-4 border-b border-borderDark flex flex-wrap items-center justify-between gap-4 bg-panel/30">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-brand-500" />
            Super Timeline Explorer
          </h2>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search event content..."
              className="px-3 py-1.5 bg-panel border border-borderDark rounded text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-brand-500 w-48"
            />

            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-panel border border-borderDark rounded text-xs text-slate-100 px-3 py-1.5 focus:outline-none focus:border-brand-500"
            >
              <option value="">All Event Types</option>
              <option value="process_start">Process Spawn</option>
              <option value="file_modified">File Modificaton</option>
              <option value="network_connection">Network Connection</option>
              <option value="registry_modified">Registry Alteration</option>
              <option value="browser_download">Browser Download</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-panel border border-borderDark rounded text-xs text-slate-100 px-3 py-1.5 focus:outline-none focus:border-brand-500"
            >
              <option value="">All Severities</option>
              <option value="high">High Severity</option>
              <option value="low">Low Severity</option>
            </select>
          </div>
        </div>

        {/* List of Events */}
        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Sorting and assembling timeline chronology...
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 text-sm italic">
            No timeline logs found matching filters.
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  <th className="table-header py-3 px-4">Timestamp (UTC)</th>
                  <th className="table-header py-3 px-4">Event Type</th>
                  <th className="table-header py-3 px-4">Details</th>
                  <th className="table-header py-3 px-4">Alert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-borderDark/20 text-xs font-sans">
                {filteredEvents.map((evt) => {
                  const isSelected = selectedEvent?.id === evt.id;
                  const isHigh = evt.severity === "high";
                  return (
                    <tr
                      key={evt.id}
                      onClick={() => setSelectedEvent(evt)}
                      className={`hover:bg-panel/40 cursor-pointer transition ${isSelected ? "bg-brand-500/10 text-brand-500 border-l-2 border-brand-500" : ""}`}
                    >
                      <td className="py-2.5 px-4 font-mono text-slate-400">
                        {evt.timestamp ? new Date(evt.timestamp).toISOString() : "Unknown"}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider font-mono bg-slate-800 text-slate-400 border border-slate-700`}>
                          {evt.event_type}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-medium text-slate-200 truncate max-w-xl" title={getEventDescription(evt)}>
                        {getEventDescription(evt)}
                      </td>
                      <td className="py-2.5 px-4">
                        {isHigh ? (
                          <span className="flex items-center gap-1 text-severity-high font-bold font-mono text-[10px] uppercase">
                            <AlertTriangle className="w-3.5 h-3.5" /> High Risk
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[10px] uppercase font-mono">Normal</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details drawer */}
      {selectedEvent && (
        <aside className="w-96 bg-panel border-l border-borderDark flex flex-col h-full text-slate-300 p-6 overflow-y-auto space-y-6">
          <div className="flex justify-between items-start border-b border-borderDark pb-4">
            <div>
              <span className="text-xs font-semibold uppercase text-brand-500 font-mono">Timeline Detail Panel</span>
              <h3 className="text-sm font-bold text-white mt-1">Chronological Event Detail</h3>
              <p className="text-xs text-slate-500 mt-0.5 font-mono">Event Type: {selectedEvent.event_type}</p>
            </div>
            <button
              onClick={() => setSelectedEvent(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-background hover:bg-slate-800 transition font-medium"
            >
              Close
            </button>
          </div>

          <div className="space-y-4 text-xs leading-relaxed">
            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1">Timestamp</h4>
              <p className="font-mono text-slate-300 bg-background border border-borderDark/40 rounded p-2.5">
                {selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toUTCString() : "N/A"}
              </p>
            </div>

            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1">Event Summary Description</h4>
              <p className="text-slate-200 bg-background border border-borderDark/40 rounded p-3 font-medium">
                {getEventDescription(selectedEvent)}
              </p>
            </div>

            <div>
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-1">Raw JSON Object attributes</h4>
              <pre className="bg-black/60 border border-borderDark/40 text-emerald-400 p-3 rounded text-[10px] overflow-x-auto leading-normal whitespace-pre-wrap font-mono break-all max-h-60 overflow-y-auto">
                {JSON.stringify(selectedEvent.details, null, 2)}
              </pre>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}
