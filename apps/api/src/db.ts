import sqlite3 from "sqlite3";
import path from "path";
import fs from "fs";

const DB_DIR = path.resolve(__dirname, "../../../data");
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const DB_PATH = path.join(DB_DIR, "forensic_workbench.db");
const db = new sqlite3.Database(DB_PATH);

export function initializeDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // 1. Cases table
      db.run(`
        CREATE TABLE IF NOT EXISTS cases (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          description TEXT,
          investigator TEXT,
          status TEXT DEFAULT 'Active',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          summary TEXT
        )
      `);

      // 2. Evidence Items table
      db.run(`
        CREATE TABLE IF NOT EXISTS evidence_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          type TEXT NOT NULL, -- 'memory' or 'disk'
          size INTEGER,
          filepath TEXT,
          hash_sha256 TEXT,
          status TEXT DEFAULT 'Pending', -- 'Pending', 'Processing', 'Completed', 'Failed'
          logs TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 3. Processes table
      db.run(`
        CREATE TABLE IF NOT EXISTS processes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          pid INTEGER NOT NULL,
          ppid INTEGER NOT NULL,
          name TEXT NOT NULL,
          path TEXT,
          create_time TEXT,
          offset TEXT,
          dll_count INTEGER DEFAULT 0,
          connection_count INTEGER DEFAULT 0,
          cross_view_mismatch INTEGER DEFAULT 0,
          cross_view_visible_count INTEGER DEFAULT 0,
          is_suspicious INTEGER DEFAULT 0,
          risk_score INTEGER DEFAULT 0,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 4. Files table
      db.run(`
        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          size INTEGER,
          inode INTEGER,
          is_deleted INTEGER DEFAULT 0,
          mtime TEXT,
          atime TEXT,
          ctime TEXT,
          crtime TEXT,
          yara_hit TEXT,
          sha256 TEXT,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 5. Network Connections table
      db.run(`
        CREATE TABLE IF NOT EXISTS network_connections (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          pid INTEGER NOT NULL,
          protocol TEXT,
          local_address TEXT,
          local_port INTEGER,
          remote_address TEXT,
          remote_port INTEGER,
          state TEXT,
          created TEXT,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 6. Registry Entries table
      db.run(`
        CREATE TABLE IF NOT EXISTS registry_entries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          hive TEXT NOT NULL,
          key_path TEXT NOT NULL,
          value_name TEXT,
          value_data TEXT,
          last_written TEXT,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 7. Persistence Items table
      db.run(`
        CREATE TABLE IF NOT EXISTS persistence (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          type TEXT NOT NULL, -- 'RunKey', 'Service', 'ScheduledTask', 'WMI', 'Cron', 'LaunchDaemon'
          name TEXT NOT NULL,
          target_path TEXT,
          command_line TEXT,
          score INTEGER DEFAULT 0,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 8. Browser Activity table
      db.run(`
        CREATE TABLE IF NOT EXISTS browser_activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          browser TEXT NOT NULL, -- 'Chrome', 'Firefox', 'Safari', 'Edge'
          type TEXT NOT NULL, -- 'history' or 'download'
          url TEXT,
          title TEXT,
          timestamp TEXT,
          download_path TEXT,
          file_size INTEGER,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 9. Alerts table
      db.run(`
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          type TEXT NOT NULL,
          severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low'
          score INTEGER NOT NULL,
          process TEXT,
          pid INTEGER,
          path TEXT,
          reason TEXT,
          details TEXT,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 10. Timeline Events table
      db.run(`
        CREATE TABLE IF NOT EXISTS timeline_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          timestamp TEXT NOT NULL,
          event_type TEXT NOT NULL, -- 'process_start', 'file_modified', 'network_connection', 'registry_modified', 'browser_download'
          details_json TEXT NOT NULL,
          severity TEXT DEFAULT 'low',
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 11. Case Notes table
      db.run(`
        CREATE TABLE IF NOT EXISTS case_notes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          author TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
      `);

      // 12. Yara Rules table
      db.run(`
        CREATE TABLE IF NOT EXISTS yara_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          content TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `, (err) => {
        if (err) {
          reject(err);
        } else {
          // Pre-populate sample YARA rules if empty
          db.get("SELECT COUNT(*) as count FROM yara_rules", (errRow, row: any) => {
            if (!errRow && row && row.count === 0) {
              const now = new Date().toISOString();
              db.run(`
                INSERT INTO yara_rules (name, content, created_at, updated_at)
                VALUES (
                  'Suspicious_Rules_Pack',
                  'rule Suspicious_PowerShell\\n{\\n    meta:\\n        author = \"ForensiCore XDR\"\\n        description = \"Flags encoded command usage\"\\n        severity = \"medium\"\\n    strings:\\n        $a = \"powershell -enc\" nocase\\n        $b = \"IEX(\" nocase\\n    condition:\\n        any of them\\n}\\n\\nrule Suspicious_Mimikatz_Keyword\\n{\\n    meta:\\n        author = \"ForensiCore XDR\"\\n        description = \"Simple Mimikatz keyword indicator\"\\n        severity = \"high\"\\n    strings:\\n        $a = \"sekurlsa::logonpasswords\" nocase\\n        $b = \"mimikatz\" nocase\\n    condition:\\n        any of them\\n}',
                  '${now}',
                  '${now}'
                )
              `);
            }
          });
          resolve();
        }
      });
    });
  });
}

// Promise-based SQL helpers
export function dbRun(sql: string, params: any[] = []): Promise<{ lastID: number; changes: number }> {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (this: any, err) {
      if (err) {
        reject(err);
      } else {
        resolve({ lastID: this.lastID, changes: this.changes });
      }
    });
  });
}

export function dbGet<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row as T);
      }
    });
  });
}

export function dbAll<T = any>(sql: string, params: any[] = []): Promise<T[]> {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows as T[]);
      }
    });
  });
}

export function closeDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    db.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
