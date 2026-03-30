const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'scopeguard.sqlite');

let db;

async function initDb() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      action TEXT NOT NULL,
      api TEXT NOT NULL,
      scope_used TEXT NOT NULL,
      risk_level TEXT NOT NULL,
      status TEXT NOT NULL,
      user_id TEXT,
      details TEXT
    )
  `);

  save();
  return db;
}

function save() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function logAction({ action, api, scope_used, risk_level, status, user_id, details }) {
  if (!db) throw new Error('Database not initialized');

  db.run(
    `INSERT INTO audit_log (action, api, scope_used, risk_level, status, user_id, details)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [action, api, scope_used, risk_level, status, user_id || 'anonymous', details || null]
  );
  save();
}

function getLog() {
  if (!db) return [];
  const results = db.exec('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100');
  if (results.length === 0) return [];

  const columns = results[0].columns;
  return results[0].values.map(row => {
    const obj = {};
    columns.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
}

module.exports = { initDb, logAction, getLog };
