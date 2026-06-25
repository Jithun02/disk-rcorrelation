import React, { useState, useEffect } from "react";
import { FileText, Send, User, Calendar, ExternalLink } from "lucide-react";

interface Note {
  id: number;
  author: string;
  note: string;
  created_at: string;
}

export default function CaseNotesReports({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [newNote, setNewNote] = useState<string>("");
  const [author, setAuthor] = useState<string>("Analyst");
  const [loadingNotes, setLoadingNotes] = useState<boolean>(true);

  const mockNotes: Note[] = [
    { id: 1, author: "Tier 3 Analyst", note: "Initial scoping of memory dump completed. Mapped 39 processes and flagged a hidden BRNIPMON.exe process mismatch. Initiating YARA rules scanning.", created_at: "2026-06-25T05:00:00.000Z" },
    { id: 2, author: "Tier 3 Analyst", note: "Outbound C2 connection detected from PID 4200 (svchost_mal.exe) running out of C:\\Windows\\Temp. Cross-referencing path missing files.", created_at: "2026-06-25T05:10:00.000Z" }
  ];

  useEffect(() => {
    fetchNotes();
  }, [caseId, isStatic]);

  const fetchNotes = async () => {
    if (isStatic) {
      setNotes(prev => prev.length ? prev : mockNotes);
      setLoadingNotes(false);
      return;
    }
    try {
      setLoadingNotes(true);
      const res = await fetch(`/api/cases/${caseId}/notes`);
      if (res.ok) {
        const data = await res.json();
        setNotes(data);
      }
    } catch (err) {
      console.error(err);
      setNotes(mockNotes);
    } finally {
      setLoadingNotes(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;

    if (isStatic) {
      const newMockNote: Note = {
        id: Math.floor(Math.random() * 1000) + 10,
        author: author || "Analyst",
        note: newNote,
        created_at: new Date().toISOString()
      };
      setNotes(prev => [newMockNote, ...prev]);
      setNewNote("");
      return;
    }

    try {
      const res = await fetch(`/api/cases/${caseId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ author, note: newNote })
      });
      if (res.ok) {
        setNewNote("");
        fetchNotes();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleOpenReport = () => {
    if (isStatic) {
      const reportHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>ForensiCore Analyst Report - Simulated Case</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; margin: 40px; background: #fafafa; }
            .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
            .header { border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; }
            h1 { margin: 0; color: #1e3a8a; }
            h2 { color: #1e40af; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; margin-top: 40px; }
            .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; background: #f3f4f6; padding: 20px; border-radius: 6px; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { border: 1px solid #e5e7eb; padding: 10px; text-align: left; }
            th { background: #f9fafb; font-weight: 600; }
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
            .badge-critical { background: #fee2e2; color: #991b1b; }
            .badge-high { background: #ffedd5; color: #9a3412; }
            .badge-medium { background: #fef9c3; color: #854d0e; }
            .badge-low { background: #ecfdf5; color: #065f46; }
            .note-item { border-left: 4px solid #3b82f6; padding-left: 15px; margin-bottom: 15px; background: #f9fafb; padding: 10px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>ForensiCore XDR Forensics Workbench</h1>
              <p>Case Forensic Triage Analyst Report (Simulated Client-Side Export)</p>
            </div>
            
            <div class="meta-grid">
              <div>
                <strong>Case Name:</strong> Simulation Demo Case<br>
                <strong>Case Status:</strong> Active<br>
                <strong>Investigator:</strong> Tier 3 Analyst
              </div>
              <div>
                <strong>Created:</strong> ${new Date().toLocaleDateString()}<br>
                <strong>Updated:</strong> ${new Date().toLocaleDateString()}<br>
                <strong>Total Alerts:</strong> 3 findings
              </div>
            </div>

            <h2>Executive Summary</h2>
            <p>Default in-memory triage case. (Running in Client-Side Simulation Mode)</p>

            <h2>Alert Summary (3)</h2>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Process / PID</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><span class="badge badge-critical">CRITICAL</span></td>
                  <td>fileless_malware_candidate</td>
                  <td>svchost_mal.exe (4200)</td>
                  <td>Process running out of temp directory with missing on-disk matching executable.</td>
                </tr>
                <tr>
                  <td><span class="badge badge-high">HIGH</span></td>
                  <td>hidden_process_psxview_mismatch</td>
                  <td>BRNIPMON.exe (2404)</td>
                  <td>Process has inconsistent visibility in psxview checks.</td>
                </tr>
                <tr>
                  <td><span class="badge badge-medium">MEDIUM</span></td>
                  <td>suspicious_process_name</td>
                  <td>svchost_mal.exe (4200)</td>
                  <td>Process name mimicks system process svchost.exe.</td>
                </tr>
              </tbody>
            </table>

            <h2>Analyst Case Notes</h2>
            ${notes.map(n => `
              <div class="note-item">
                <strong>${n.author}</strong> <small>at ${new Date(n.created_at).toLocaleString()}</small>
                <p>${n.note}</p>
              </div>
            `).join("")}

          </div>
        </body>
        </html>
      `;
      const reportWindow = window.open("", "_blank");
      if (reportWindow) {
        reportWindow.document.write(reportHtml);
        reportWindow.document.close();
      }
      return;
    }
    window.open(`/api/cases/${caseId}/report`, "_blank");
  };

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* Team Notes Logger */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-borderDark bg-background/40">
        <div className="p-4 border-b border-borderDark bg-panel/30">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-brand-500" />
            Case Investigation Notes
          </h2>
        </div>

        {/* Note input form */}
        <div className="p-6 border-b border-borderDark bg-panel/10">
          <form onSubmit={handleAddNote} className="space-y-4">
            <div className="flex gap-4">
              <div className="w-1/4">
                <label className="block text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-2">
                  Author Signature
                </label>
                <input
                  type="text"
                  value={author}
                  onChange={(e) => setAuthor(e.target.value)}
                  placeholder="Analyst Name"
                  className="w-full bg-background border border-borderDark rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-brand-500"
                />
              </div>
              <div className="flex-1">
                <label className="block text-[10px] font-semibold text-slate-500 uppercase tracking-widest font-mono mb-2">
                  Investigative Activity Note
                </label>
                <textarea
                  rows={2}
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Record file analyses, malware execution flow markers, timeline deductions..."
                  className="w-full bg-background border border-borderDark rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-brand-500 resize-none"
                />
              </div>
            </div>
            <div className="flex justify-end">
              <button
                type="submit"
                className="px-4 py-2 bg-brand-500 hover:bg-brand-600 rounded text-xs font-semibold tracking-wide transition flex items-center gap-1.5"
              >
                <Send className="w-3.5 h-3.5" /> Log Case Note
              </button>
            </div>
          </form>
        </div>

        {/* Notes Listing */}
        {loadingNotes ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Fetching logged activities...
          </div>
        ) : notes.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 text-sm italic p-8 text-center max-w-md mx-auto">
            No active notes logged. Compile updates and findings using the log workspace above.
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {notes.map((note) => (
              <div key={note.id} className="bg-panel/40 border border-borderDark/60 rounded-lg p-4 space-y-3">
                <div className="flex justify-between items-center text-xs border-b border-borderDark/40 pb-2">
                  <div className="flex items-center gap-1.5 text-slate-200 font-semibold">
                    <User className="w-3.5 h-3.5 text-slate-500" />
                    {note.author}
                  </div>
                  <div className="flex items-center gap-1 text-slate-500 font-mono">
                    <Calendar className="w-3.5 h-3.5" />
                    {new Date(note.created_at).toLocaleString()}
                  </div>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">{note.note}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Analyst Report Generator controls */}
      <aside className="w-96 bg-panel border-l border-borderDark flex flex-col h-full text-slate-300 p-6 overflow-y-auto space-y-6">
        <div className="border-b border-borderDark pb-4">
          <span className="text-xs font-semibold uppercase text-brand-500 font-mono">Reporting Center</span>
          <h3 className="text-sm font-bold text-white mt-1">Export Analyst Summary</h3>
          <p className="text-xs text-slate-500 mt-0.5">Produce commercial-grade forensic compliance packages</p>
        </div>

        <div className="bg-background/40 border border-borderDark/50 rounded-lg p-4 space-y-4">
          <h4 className="text-xs font-semibold text-white">Analyst Report Package</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            The reporting compiler aggregates:
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 list-disc pl-4 font-sans leading-normal">
            <li>Locker Case Scoping Meta</li>
            <li>Timeline Chronology</li>
            <li>Risk-ranked Process trees</li>
            <li>Persistent registries and browser logs</li>
            <li>Logged Team Analyst Notes</li>
          </ul>

          <div className="pt-2 border-t border-borderDark/30">
            <button
              onClick={handleOpenReport}
              className="w-full py-2.5 bg-brand-500 hover:bg-brand-600 rounded text-sm text-white font-semibold transition flex items-center justify-center gap-2"
            >
              Compile & Open Report <ExternalLink className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="bg-slate-500/5 border border-borderDark/40 rounded p-4 text-xs text-slate-400 font-sans leading-relaxed">
          <strong>Tip:</strong> Standalone report files compile to clean responsive HTML markup, which can be printed to PDF directly from the browser for presentation to audit teams and legal counsel.
        </div>
      </aside>
    </div>
  );
}
