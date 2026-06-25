import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import { exec } from "child_process";
import { dbAll, dbRun, dbGet } from "./db";

const router = express.Router();

// Helper to run python forensic worker in the background
function runForensicWorker(
  caseId: number,
  evidenceId: number,
  memoryPath: string | null,
  diskPath: string | null,
  yaraRulesPath: string | null,
  mode: "live" | "simulation"
) {
  let pythonBin = "python3";
  const venvPythonPath = path.resolve(__dirname, "../../../.venv/bin/python");
  const venvPythonPathExe = path.resolve(__dirname, "../../../.venv/Scripts/python.exe");
  if (fs.existsSync(venvPythonPath)) {
    pythonBin = venvPythonPath;
  } else if (fs.existsSync(venvPythonPathExe)) {
    pythonBin = venvPythonPathExe;
  } else {
    pythonBin = process.platform === "win32" ? "python" : "python3";
  }
  const workerPath = path.resolve(__dirname, "../../../core_forensics/worker.py");
  
  let cmd = `"${pythonBin}" "${workerPath}" --mode ${mode}`;
  if (memoryPath) cmd += ` --memory-file "${memoryPath}"`;
  if (diskPath) cmd += ` --disk-image "${diskPath}"`;
  if (yaraRulesPath) cmd += ` --yara-rules "${yaraRulesPath}"`;

  console.log(`[API Job Run] Executing command: ${cmd}`);

  // Set evidence status to Processing
  dbRun("UPDATE evidence_items SET status = 'Processing', logs = ? WHERE id = ?", [
    `Started job at ${new Date().toISOString()}`,
    evidenceId
  ]);

  exec(cmd, { maxBuffer: 1024 * 1024 * 50 }, async (error, stdout, stderr) => {
    const logs = `STDOUT:\n${stdout.substring(0, 5000)}\n\nSTDERR:\n${stderr}`;
    if (error) {
      console.error(`[Worker Error] ${error.message}`);
      await dbRun("UPDATE evidence_items SET status = 'Failed', logs = ? WHERE id = ?", [
        `${logs}\n\nERROR: ${error.message}`,
        evidenceId
      ]);
      return;
    }

    try {
      const data = JSON.parse(stdout);
      
      // Update case summary
      const summaryText = JSON.stringify(data.summary || {});
      await dbRun("UPDATE cases SET summary = ?, updated_at = ? WHERE id = ?", [
        summaryText,
        new Date().toISOString(),
        caseId
      ]);

      // Insert Processes
      const processes = data.raw?.processes || [];
      const processesDict = new Map<number, number>(); // Map PID -> db ID
      for (const proc of processes) {
        // Correlate metrics
        const corr = (data.correlated || []).find((c: any) => c.pid === proc.pid) || {};
        const dllCount = corr.dll_count || 0;
        const connCount = corr.connection_count || 0;
        const isSuspicious = corr.path_suspicious || corr.path_missing || corr.cross_view_mismatch ? 1 : 0;
        let riskScore = 0;
        if (corr.path_suspicious) riskScore += 40;
        if (corr.path_missing) riskScore += 30;
        if (corr.cross_view_mismatch) riskScore += 50;

        const res = await dbRun(
          `INSERT INTO processes (case_id, pid, ppid, name, path, create_time, offset, dll_count, connection_count, cross_view_mismatch, cross_view_visible_count, is_suspicious, risk_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            caseId,
            proc.pid,
            proc.ppid || 0,
            proc.name || proc.process || "unknown",
            proc.path || corr.image_path || null,
            proc.create_time || null,
            proc.offset || null,
            dllCount,
            connCount,
            corr.cross_view_mismatch ? 1 : 0,
            corr.cross_view_visible_count || 0,
            isSuspicious,
            riskScore
          ]
        );
        processesDict.set(proc.pid, res.lastID);
      }

      // Insert Disk Files
      const files = data.raw?.files || [];
      for (const file of files) {
        const yaraHit = (data.yara?.matches || []).find((m: any) => m.path === file.path);
        const yaraHitStr = yaraHit ? JSON.stringify(yaraHit) : null;
        await dbRun(
          `INSERT INTO files (case_id, path, size, inode, is_deleted, mtime, atime, ctime, crtime, yara_hit, sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            caseId,
            file.path,
            file.size || null,
            file.inode || null,
            file.is_deleted ? 1 : 0,
            file.mtime || null,
            file.atime || null,
            file.ctime || null,
            file.crtime || null,
            yaraHitStr,
            file.sha256 || null
          ]
        );
      }

      // Insert Connections
      const connections = data.raw?.connections || [];
      for (const conn of connections) {
        await dbRun(
          `INSERT INTO network_connections (case_id, pid, protocol, local_address, local_port, remote_address, remote_port, state, created)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            caseId,
            conn.pid,
            conn.protocol || "TCP",
            conn.local_address || null,
            conn.local_port || null,
            conn.remote_address || null,
            conn.remote_port || null,
            conn.state || null,
            conn.created || null
          ]
        );
      }

      // Insert Registry Entries
      const registryEntries = data.registry_entries || [];
      for (const entry of registryEntries) {
        await dbRun(
          `INSERT INTO registry_entries (case_id, hive, key_path, value_name, value_data, last_written)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [caseId, entry.hive, entry.key_path, entry.value_name, entry.value_data, entry.last_written || null]
        );
      }

      // Insert Persistence items
      const persistenceItems = data.persistence_items || [];
      for (const item of persistenceItems) {
        await dbRun(
          `INSERT INTO persistence (case_id, type, name, target_path, command_line, score)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [caseId, item.type, item.name, item.target_path, item.command_line, item.score || 0]
        );
      }

      // Insert Browser activity
      const browserActivity = data.browser_activity || [];
      for (const act of browserActivity) {
        await dbRun(
          `INSERT INTO browser_activity (case_id, browser, type, url, title, timestamp, download_path, file_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [caseId, act.browser, act.type, act.url, act.title, act.timestamp, act.download_path, act.file_size]
        );
      }

      // Insert Alerts
      const alerts = data.alerts || [];
      for (const alert of alerts) {
        await dbRun(
          `INSERT INTO alerts (case_id, type, severity, score, process, pid, path, reason, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            caseId,
            alert.type,
            alert.severity || "medium",
            alert.score || 50,
            alert.process || null,
            alert.pid || null,
            alert.path || null,
            alert.reason || null,
            alert.details || JSON.stringify(alert.checks || alert)
          ]
        );
      }

      // Insert Timeline Events
      const timeline = data.timeline || [];
      for (const event of timeline) {
        let severity = "low";
        // Elevate severity if linked to alert process
        const hasAlert = alerts.some((a: any) => a.pid === event.pid || a.process === event.name);
        if (hasAlert) {
          severity = "high";
        }
        const ts = event.timestamp || data.generated_at || new Date().toISOString();
        await dbRun(
          `INSERT INTO timeline_events (case_id, timestamp, event_type, details_json, severity)
           VALUES (?, ?, ?, ?, ?)`,
          [caseId, ts, event.event || "log", JSON.stringify(event), severity]
        );
      }

      // Set evidence status to Completed
      await dbRun("UPDATE evidence_items SET status = 'Completed', logs = ? WHERE id = ?", [
        `Ingested all forensic items at ${new Date().toISOString()}`,
        evidenceId
      ]);
      console.log(`[API Job Run] Successfully completed case ${caseId} ingestion.`);

    } catch (parseErr: any) {
      console.error(`[Data Parsing Error] ${parseErr.message}`);
      dbRun("UPDATE evidence_items SET status = 'Failed', logs = ? WHERE id = ?", [
        `${logs}\n\nPARSING ERROR: ${parseErr.message}`,
        evidenceId
      ]);
    }
  });
}

// ----------------------------------------------------
// CASES ROUTES
// ----------------------------------------------------
router.get("/cases", async (req, res) => {
  try {
    const cases = await dbAll("SELECT * FROM cases ORDER BY id DESC");
    res.json(cases.map(c => ({
      ...c,
      summary: c.summary ? JSON.parse(c.summary) : null
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/cases", async (req, res) => {
  const { name, description, investigator } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Case name is required" });
  }
  try {
    const now = new Date().toISOString();
    const result = await dbRun(
      "INSERT INTO cases (name, description, investigator, status, created_at, updated_at) VALUES (?, ?, ?, 'Active', ?, ?)",
      [name, description || "", investigator || "Analyst", now, now]
    );
    res.status(201).json({ id: result.lastID, name, description, investigator, status: "Active" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const caseItem = await dbGet("SELECT * FROM cases WHERE id = ?", [caseId]);
    if (!caseItem) {
      return res.status(404).json({ error: "Case not found" });
    }
    caseItem.summary = caseItem.summary ? JSON.parse(caseItem.summary) : null;
    res.json(caseItem);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/cases/:id", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    await dbRun("DELETE FROM cases WHERE id = ?", [caseId]);
    res.json({ message: "Case and all items deleted successfully" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// EVIDENCE ROUTES
// ----------------------------------------------------
router.get("/cases/:id/evidence", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const items = await dbAll("SELECT * FROM evidence_items WHERE case_id = ?", [caseId]);
    res.json(items);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/cases/:id/evidence", async (req, res) => {
  const caseId = parseInt(req.params.id);
  const { name, type, memoryPath, diskPath, mode } = req.body;

  if (!name || !type) {
    return res.status(400).json({ error: "Evidence name and type required" });
  }

  try {
    const now = new Date().toISOString();
    const result = await dbRun(
      "INSERT INTO evidence_items (case_id, name, type, filepath, status, created_at) VALUES (?, ?, ?, ?, 'Pending', ?)",
      [caseId, name, type, type === "memory" ? memoryPath : diskPath, now]
    );

    // Fetch default YARA rules from db if available
    const rules = await dbGet("SELECT content FROM yara_rules ORDER BY id DESC LIMIT 1");
    let yaraPath: string | null = null;
    if (rules) {
      const tempRulesPath = path.resolve(__dirname, "../../../data/temp_rules.yar");
      fs.writeFileSync(tempRulesPath, rules.content);
      yaraPath = tempRulesPath;
    }

    // Trigger python execution
    runForensicWorker(
      caseId,
      result.lastID,
      type === "memory" ? memoryPath : null,
      type === "disk" ? diskPath : null,
      yaraPath,
      mode || "live"
    );

    res.status(202).json({ id: result.lastID, message: "Evidence ingestion triggered" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// EXPLORER DATA ROUTES
// ----------------------------------------------------
router.get("/cases/:id/processes", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const list = await dbAll("SELECT * FROM processes WHERE case_id = ?", [caseId]);
    res.json(list);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id/files", async (req, res) => {
  const caseId = parseInt(req.params.id);
  const search = req.query.search ? `%${req.query.search}%` : "%";
  const deletedOnly = req.query.deletedOnly === "true";
  const yaraHitOnly = req.query.yaraHitOnly === "true";

  try {
    let query = "SELECT * FROM files WHERE case_id = ? AND path LIKE ?";
    const params: any[] = [caseId, search];

    if (deletedOnly) {
      query += " AND is_deleted = 1";
    }
    if (yaraHitOnly) {
      query += " AND yara_hit IS NOT NULL";
    }

    query += " LIMIT 300"; // Cap page size
    const list = await dbAll(query, params);
    res.json(list.map(f => ({
      ...f,
      is_deleted: f.is_deleted === 1,
      yara_hit: f.yara_hit ? JSON.parse(f.yara_hit) : null
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id/file-hex", async (req, res) => {
  // In a real sandbox execution, we could parse bytes from pytsk3 or return a high-fidelity hex view structure
  // If the file path is a real file inside workspace, we read it, otherwise generate mock hexadecimal details
  const filePath = String(req.query.path || "");
  try {
    let fileBuffer: Buffer;
    if (fs.existsSync(filePath)) {
      const stats = fs.statSync(filePath);
      const readSize = Math.min(stats.size, 1024);
      const fd = fs.openSync(filePath, "r");
      fileBuffer = Buffer.alloc(readSize);
      fs.readSync(fd, fileBuffer, 0, readSize, 0);
      fs.closeSync(fd);
    } else {
      // Mock forensic hex file structure
      fileBuffer = Buffer.from(
        `MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00This program cannot be run in DOS mode.\r\r\n$ForensicArtifactPayloadShellcodeDataInjection\x00\x00\x45\x4b\x59\x53\x4f\x43`
      );
    }

    const hexDump = [];
    const asciiDump = [];
    const bytes = Array.from(fileBuffer);
    
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hexStr = chunk.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
      const asciiStr = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
      hexDump.push(hexStr);
      asciiDump.push(asciiStr);
    }

    res.json({
      path: filePath,
      size: bytes.length,
      hex: hexDump,
      ascii: asciiDump
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id/timeline", async (req, res) => {
  const caseId = parseInt(req.params.id);
  const typeFilter = req.query.type ? String(req.query.type) : null;
  const severityFilter = req.query.severity ? String(req.query.severity) : null;

  try {
    let query = "SELECT * FROM timeline_events WHERE case_id = ?";
    const params: any[] = [caseId];

    if (typeFilter) {
      query += " AND event_type = ?";
      params.push(typeFilter);
    }
    if (severityFilter) {
      query += " AND severity = ?";
      params.push(severityFilter);
    }

    query += " ORDER BY timestamp ASC";
    const list = await dbAll(query, params);
    res.json(list.map(evt => ({
      ...evt,
      details: JSON.parse(evt.details_json)
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id/registry", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const entries = await dbAll("SELECT * FROM registry_entries WHERE case_id = ?", [caseId]);
    const persistence = await dbAll("SELECT * FROM persistence WHERE case_id = ?", [caseId]);
    res.json({ entries, persistence });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/cases/:id/browser", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const list = await dbAll("SELECT * FROM browser_activity WHERE case_id = ?", [caseId]);
    res.json(list);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// DETECTIONS & ALERTS
// ----------------------------------------------------
router.get("/cases/:id/alerts", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const list = await dbAll("SELECT * FROM alerts WHERE case_id = ? ORDER BY score DESC", [caseId]);
    res.json(list);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// YARA RULES ROUTES
// ----------------------------------------------------
router.get("/rules", async (req, res) => {
  try {
    const rules = await dbAll("SELECT * FROM yara_rules ORDER BY id DESC");
    res.json(rules);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/rules", async (req, res) => {
  const { name, content } = req.body;
  if (!name || !content) {
    return res.status(400).json({ error: "Rule name and content required" });
  }
  try {
    const now = new Date().toISOString();
    // Use INSERT OR REPLACE
    await dbRun(
      `INSERT INTO yara_rules (name, content, created_at, updated_at) 
       VALUES (?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at`,
      [name, content, now, now]
    );
    res.json({ message: "YARA Rules saved successfully" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// CASE NOTES
// ----------------------------------------------------
router.get("/cases/:id/notes", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const list = await dbAll("SELECT * FROM case_notes WHERE case_id = ? ORDER BY id DESC", [caseId]);
    res.json(list);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/cases/:id/notes", async (req, res) => {
  const caseId = parseInt(req.params.id);
  const { author, note } = req.body;
  if (!note) {
    return res.status(400).json({ error: "Note content is required" });
  }
  try {
    const now = new Date().toISOString();
    await dbRun(
      "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (?, ?, ?, ?)",
      [caseId, author || "Analyst", note, now]
    );
    res.status(201).json({ message: "Note added successfully" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------------------------------------------
// STANDALONE REPORT GENERATOR
// ----------------------------------------------------
router.get("/cases/:id/report", async (req, res) => {
  const caseId = parseInt(req.params.id);
  try {
    const caseItem = await dbGet("SELECT * FROM cases WHERE id = ?", [caseId]);
    if (!caseItem) {
      return res.status(404).json({ error: "Case not found" });
    }

    const alerts = await dbAll("SELECT * FROM alerts WHERE case_id = ? ORDER BY score DESC", [caseId]);
    const processes = await dbAll("SELECT * FROM processes WHERE case_id = ? ORDER BY risk_score DESC", [caseId]);
    const persistence = await dbAll("SELECT * FROM persistence WHERE case_id = ? ORDER BY score DESC", [caseId]);
    const connections = await dbAll("SELECT * FROM network_connections WHERE case_id = ?", [caseId]);
    const notes = await dbAll("SELECT * FROM case_notes WHERE case_id = ? ORDER BY id DESC", [caseId]);

    const reportHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>ForensiCore Analyst Report - ${caseItem.name}</title>
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
            <p>Case Forensic Triage Analyst Report</p>
          </div>
          
          <div class="meta-grid">
            <div>
              <strong>Case Name:</strong> ${caseItem.name}<br>
              <strong>Case Status:</strong> ${caseItem.status}<br>
              <strong>Investigator:</strong> ${caseItem.investigator}
            </div>
            <div>
              <strong>Created:</strong> ${new Date(caseItem.created_at).toLocaleString()}<br>
              <strong>Updated:</strong> ${new Date(caseItem.updated_at).toLocaleString()}<br>
              <strong>Total Alerts:</strong> ${alerts.length} findings
            </div>
          </div>

          <h2>Executive Summary</h2>
          <p>${caseItem.description || "No description provided."}</p>

          <h2>Alert Summary (${alerts.length})</h2>
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
              ${alerts.map(a => `
                <tr>
                  <td><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></td>
                  <td>${a.type}</td>
                  <td>${a.process || "N/A"} (${a.pid || "N/A"})</td>
                  <td>${a.reason}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>

          <h2>Process Correlations (${processes.length})</h2>
          <table>
            <thead>
              <tr>
                <th>PID</th>
                <th>PPID</th>
                <th>Name</th>
                <th>Path</th>
                <th>Dlls</th>
                <th>Conns</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              ${processes.map(p => `
                <tr>
                  <td>${p.pid}</td>
                  <td>${p.ppid}</td>
                  <td>${p.name}</td>
                  <td>${p.path || "-"}</td>
                  <td>${p.dll_count}</td>
                  <td>${p.connection_count}</td>
                  <td><strong>${p.risk_score}</strong></td>
                </tr>
              `).join("")}
            </tbody>
          </table>

          <h2>Persistence Items (${persistence.length})</h2>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Name</th>
                <th>Target Path</th>
                <th>Command Line</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              ${persistence.map(item => `
                <tr>
                  <td>${item.type}</td>
                  <td>${item.name}</td>
                  <td>${item.target_path || "-"}</td>
                  <td><code>${item.command_line || "-"}</code></td>
                  <td>${item.score}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>

          <h2>Network Connections (${connections.length})</h2>
          <table>
            <thead>
              <tr>
                <th>PID</th>
                <th>Protocol</th>
                <th>Local Address</th>
                <th>Remote Address</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              ${connections.map(c => `
                <tr>
                  <td>${c.pid}</td>
                  <td>${c.protocol}</td>
                  <td>${c.local_address}:${c.local_port}</td>
                  <td>${c.remote_address}:${c.remote_port}</td>
                  <td>${c.state || "-"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>

          <h2>Analyst Case Notes</h2>
          ${notes.length === 0 ? "<p>No notes logged.</p>" : notes.map(n => `
            <div class="note-item">
              <strong>${n.author}</strong> <small>at ${new Date(n.created_at).toLocaleString()}</small>
              <p>${n.note}</p>
            </div>
          `).join("")}

        </div>
      </body>
      </html>
    `;

    res.setHeader("Content-Type", "text/html");
    res.send(reportHtml);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
