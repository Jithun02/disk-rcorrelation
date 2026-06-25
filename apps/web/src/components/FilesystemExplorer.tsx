import React, { useState, useEffect } from "react";
import { FolderOpen, FileText, Search, ShieldAlert, FileCode } from "lucide-react";

interface FileRecord {
  id: number;
  path: string;
  size: number | null;
  inode: number | null;
  is_deleted: boolean;
  mtime: string | null;
  atime: string | null;
  ctime: string | null;
  crtime: string | null;
  yara_hit: any | null;
  sha256: string | null;
}

interface HexData {
  path: string;
  size: number;
  hex: string[];
  ascii: string[];
}

export default function FilesystemExplorer({ caseId, isStatic }: { caseId: number; isStatic?: boolean }) {
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [selectedFile, setSelectedFile] = useState<FileRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  
  // Filters
  const [search, setSearch] = useState<string>("");
  const [deletedOnly, setDeletedOnly] = useState<boolean>(false);
  const [yaraHitOnly, setYaraHitOnly] = useState<boolean>(false);

  // Hex Drawer State
  const [showHexDrawer, setShowHexDrawer] = useState<boolean>(false);
  const [hexData, setHexData] = useState<HexData | null>(null);
  const [loadingHex, setLoadingHex] = useState<boolean>(false);

  const mockFiles: FileRecord[] = [
    { id: 1, path: "/Windows/System32/explorer.exe", size: 2871000, inode: 4012, is_deleted: false, mtime: "2026-04-01T12:00:00Z", atime: "2026-04-02T05:00:00Z", ctime: "2026-04-01T12:00:00Z", crtime: "2026-04-01T12:00:00Z", yara_hit: null, sha256: "b45a6c38d8ef51ef4081c2018a1a36184a2123d" },
    { id: 2, path: "/Windows/System32/svchost.exe", size: 51200, inode: 5512, is_deleted: false, mtime: "2026-04-01T12:00:00Z", atime: "2026-04-02T05:00:00Z", ctime: "2026-04-01T12:00:00Z", crtime: "2026-04-01T12:00:00Z", yara_hit: null, sha256: "913ad81e600f12fa91ca8e1c6018afc6e131cd" },
    { id: 3, path: "/Windows/System32/cmd.exe", size: 272000, inode: 6128, is_deleted: false, mtime: "2026-04-01T12:00:00Z", atime: "2026-04-02T05:00:00Z", ctime: "2026-04-01T12:00:00Z", crtime: "2026-04-01T12:00:00Z", yara_hit: null, sha256: "ea819b183610cfec9a1abfc6192acbfeba09cf" },
    { id: 4, path: "/Users/Administrator/Downloads/invoice_pdf.exe", size: 182300, inode: 9920, is_deleted: true, mtime: "2026-04-02T06:12:45Z", atime: "2026-04-02T06:12:45Z", ctime: "2026-04-02T06:12:45Z", crtime: "2026-04-02T06:12:45Z", yara_hit: { rule: "Suspicious_PowerShell", meta: { author: "ForensiCore XDR", description: "Detects base64 encoded payload executions" }, matched_strings: ["$a: powershell -enc", "$b: IEX("] }, sha256: "c18a209b55282acb55018f28fa9b19e785a192c" },
    { id: 5, path: "/Windows/Temp/payload.bin", size: 204800, inode: 9921, is_deleted: false, mtime: "2026-04-02T07:15:34Z", atime: "2026-04-02T07:15:34Z", ctime: "2026-04-02T07:15:34Z", crtime: "2026-04-02T07:15:34Z", yara_hit: null, sha256: "3ba71891cf28abced189cfa110acfb50901c0cf" }
  ];

  useEffect(() => {
    fetchFiles();
  }, [caseId, search, deletedOnly, yaraHitOnly, isStatic]);

  const fetchFiles = async () => {
    if (isStatic) {
      let filtered = [...mockFiles];
      if (search) {
        filtered = filtered.filter(f => f.path.toLowerCase().includes(search.toLowerCase()));
      }
      if (deletedOnly) {
        filtered = filtered.filter(f => f.is_deleted);
      }
      if (yaraHitOnly) {
        filtered = filtered.filter(f => f.yara_hit !== null);
      }
      setFiles(filtered);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (deletedOnly) params.append("deletedOnly", "true");
      if (yaraHitOnly) params.append("yaraHitOnly", "true");
      
      const res = await fetch(`/api/cases/${caseId}/files?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setFiles(data);
      }
    } catch (err) {
      console.error(err);
      setFiles(mockFiles);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenHexView = async (path: string) => {
    try {
      setShowHexDrawer(true);
      setLoadingHex(true);
      setHexData(null);
      
      if (isStatic) {
        setTimeout(() => {
          setHexData({
            path: path,
            size: 96,
            hex: [
              "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
              "B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00",
              "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E",
              "6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F",
              "53 20 6D 6F 64 65 2E 0D 0D 0A 24 46 6F 72 65 6E",
              "73 69 63 41 72 74 69 66 61 63 74 50 61 79 6C 6F"
            ],
            ascii: [
              "MZ..............",
              "........@.......",
              "This program can",
              "not be run in DO",
              "S mode....$Foren",
              "sicArtifactPaylo"
            ]
          });
          setLoadingHex(false);
        }, 300);
        return;
      }
      
      const res = await fetch(`/api/cases/${caseId}/file-hex?path=${encodeURIComponent(path)}`);
      if (res.ok) {
        const data = await res.json();
        setHexData(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingHex(false);
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* File List Grid */}
      <div className="flex-1 flex flex-col min-w-0 bg-background/40">
        {/* Toolbar */}
        <div className="p-4 border-b border-borderDark flex flex-wrap items-center justify-between gap-4 bg-panel/30">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FolderOpen className="w-5 h-5 text-brand-500" />
            Filesystem Explorer
          </h2>

          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search file path..."
                className="pl-8 pr-3 py-1.5 bg-panel border border-borderDark rounded text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-brand-500 w-60"
              />
            </div>

            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={deletedOnly}
                onChange={(e) => setDeletedOnly(e.target.checked)}
                className="rounded bg-panel border-borderDark text-brand-500 focus:ring-0 focus:ring-offset-0 w-3.5 h-3.5"
              />
              Deleted Files Only
            </label>

            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={yaraHitOnly}
                onChange={(e) => setYaraHitOnly(e.target.checked)}
                className="rounded bg-panel border-borderDark text-brand-500 focus:ring-0 focus:ring-offset-0 w-3.5 h-3.5"
              />
              YARA Hits Only
            </label>
          </div>
        </div>

        {/* Table */}
        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Searching disk volumes filesystem...
          </div>
        ) : files.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 text-sm italic">
            No files matched your filters.
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr>
                  <th className="table-header py-3 px-4">Inode</th>
                  <th className="table-header py-3 px-4">File Path</th>
                  <th className="table-header py-3 px-4">Size (Bytes)</th>
                  <th className="table-header py-3 px-4">Status</th>
                  <th className="table-header py-3 px-4">Modified (M)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-borderDark/20 text-xs">
                {files.map((file) => {
                  const isSelected = selectedFile?.id === file.id;
                  return (
                    <tr
                      key={file.id}
                      onClick={() => setSelectedFile(file)}
                      className={`hover:bg-panel/40 cursor-pointer transition ${isSelected ? "bg-brand-500/10 text-brand-500 border-l-2 border-brand-500" : ""}`}
                    >
                      <td className="py-2.5 px-4 font-mono text-slate-500">{file.inode || "-"}</td>
                      <td className="py-2.5 px-4 font-medium text-slate-200">
                        <div className="flex items-center gap-2">
                          <FileText className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                          <span className="truncate max-w-lg" title={file.path}>
                            {file.path}
                          </span>
                          {file.yara_hit && (
                            <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-500 border border-red-500/20 text-[9px] font-bold uppercase tracking-wider font-mono">
                              YARA: {file.yara_hit.rule}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300">
                        {file.size ? file.size.toLocaleString() : "0"}
                      </td>
                      <td className="py-2.5 px-4">
                        {file.is_deleted ? (
                          <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-500 border border-red-500/20 font-bold uppercase tracking-wide text-[9px]">
                            Deleted
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 uppercase tracking-wide text-[9px]">
                            Allocated
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-400">
                        {file.mtime ? new Date(file.mtime).toLocaleString() : "-"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details Side drawer */}
      {selectedFile && (
        <aside className="w-96 bg-panel border-l border-borderDark flex flex-col h-full text-slate-300 p-6 overflow-y-auto space-y-6">
          <div className="flex justify-between items-start border-b border-borderDark pb-4">
            <div>
              <span className="text-xs font-semibold uppercase text-brand-500 font-mono">File Details Panel</span>
              <h3 className="text-sm font-bold text-white mt-1 break-all">{selectedFile.path.split("/").pop()}</h3>
              <p className="text-xs text-slate-500 mt-0.5 font-mono">Inode: {selectedFile.inode || "N/A"}</p>
            </div>
            <button
              onClick={() => setSelectedFile(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-background hover:bg-slate-800 transition font-medium"
            >
              Close
            </button>
          </div>

          {/* Action button: Hex View */}
          <button
            onClick={() => handleOpenHexView(selectedFile.path)}
            className="w-full py-2 bg-brand-500 hover:bg-brand-600 rounded text-sm text-white font-semibold transition"
          >
            Open Hex / Strings Drawer
          </button>

          {/* Alert if YARA match */}
          {selectedFile.yara_hit && (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-4 text-xs text-red-400 space-y-2">
              <div className="flex gap-2 items-center font-bold text-red-200">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>YARA Rule Alert: {selectedFile.yara_hit.rule}</span>
              </div>
              <p className="leading-relaxed">
                Description: {selectedFile.yara_hit.meta?.description || "No description provided."}<br />
                Author: {selectedFile.yara_hit.meta?.author || "N/A"}<br />
                Strings Matched:
              </p>
              <div className="bg-background/40 rounded p-2 font-mono text-[10px] text-slate-300 break-all space-y-1">
                {(selectedFile.yara_hit.matched_strings || []).map((s: string, idx: number) => (
                  <div key={idx}>{s}</div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata Grid */}
          <div className="space-y-4 text-xs">
            <h4 className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest font-mono">MACB Timestamps</h4>
            <div className="grid grid-cols-2 gap-y-3 gap-x-2 bg-background/40 border border-borderDark/40 rounded p-3 font-mono">
              <span className="text-slate-500">Modified (M):</span>
              <span className="text-slate-300 truncate" title={selectedFile.mtime || "N/A"}>{selectedFile.mtime ? new Date(selectedFile.mtime).toLocaleString() : "N/A"}</span>
              <span className="text-slate-500">Accessed (A):</span>
              <span className="text-slate-300 truncate" title={selectedFile.atime || "N/A"}>{selectedFile.atime ? new Date(selectedFile.atime).toLocaleString() : "N/A"}</span>
              <span className="text-slate-500">Metadata (C):</span>
              <span className="text-slate-300 truncate" title={selectedFile.ctime || "N/A"}>{selectedFile.ctime ? new Date(selectedFile.ctime).toLocaleString() : "N/A"}</span>
              <span className="text-slate-500">Created (B):</span>
              <span className="text-slate-300 truncate" title={selectedFile.crtime || "N/A"}>{selectedFile.crtime ? new Date(selectedFile.crtime).toLocaleString() : "N/A"}</span>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <h4 className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest font-mono">Hash & Location Properties</h4>
            <div className="space-y-2 bg-background/20 border border-borderDark/40 rounded p-3 font-mono text-[10px]">
              <div>
                <span className="text-slate-500">Size (Bytes):</span><br />
                <span className="text-slate-300">{selectedFile.size ? selectedFile.size.toLocaleString() : "0"} bytes</span>
              </div>
              <div className="pt-2 border-t border-borderDark/20">
                <span className="text-slate-500">SHA-256 Hex Digest:</span><br />
                <span className="text-slate-400 break-all">{selectedFile.sha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}</span>
              </div>
              <div className="pt-2 border-t border-borderDark/20">
                <span className="text-slate-500">Volume File Path:</span><br />
                <span className="text-slate-400 break-all">{selectedFile.path}</span>
              </div>
            </div>
          </div>
        </aside>
      )}

      {/* Hex Viewer overlay Drawer */}
      {showHexDrawer && (
        <div className="fixed inset-y-0 right-0 z-50 w-[600px] bg-[#0c101b] border-l border-borderDark shadow-2xl p-6 flex flex-col">
          <div className="flex justify-between items-center border-b border-borderDark pb-4 mb-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileCode className="w-5 h-5 text-brand-500" /> Hex / String Reader
              </h3>
              <p className="text-xs text-slate-500 truncate max-w-md" title={hexData?.path}>{hexData?.path || "Reading file stream..."}</p>
            </div>
            <button
              onClick={() => setShowHexDrawer(false)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition font-medium"
            >
              Close Reader
            </button>
          </div>

          {loadingHex ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-400 text-xs">
              <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-brand-500 mb-3"></div>
              Reading sectors and parsing binary headers...
            </div>
          ) : hexData ? (
            <div className="flex-1 flex overflow-hidden border border-borderDark/60 bg-black/40 rounded p-4 font-mono text-[10px]">
              {/* Byte offsets */}
              <div className="text-slate-600 select-none border-r border-borderDark/60 pr-3 flex flex-col text-right">
                {hexData.hex.map((_, idx) => (
                  <div key={idx}>{(idx * 16).toString(16).padStart(8, "0").toUpperCase()}:</div>
                ))}
              </div>

              {/* Hex codes */}
              <div className="flex-1 overflow-x-auto text-emerald-400 px-4 whitespace-nowrap flex flex-col">
                {hexData.hex.map((line, idx) => (
                  <div key={idx}>{line}</div>
                ))}
              </div>

              {/* Ascii codes */}
              <div className="text-slate-400 select-none border-l border-borderDark/60 pl-3 whitespace-nowrap flex flex-col">
                {hexData.ascii.map((line, idx) => (
                  <div key={idx}>{line}</div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-red-500 text-xs italic">
              Error reading bytes from SleuthKit volume.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
