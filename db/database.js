const initSqlJs = require('sql.js');

let db;

async function initDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();

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

  // Seed with realistic demo entries so audit log is never empty
  const seedEntries = [
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
      action: 'User login',
      api: 'Auth0',
      scope_used: 'openid profile email',
      risk_level: 'low',
      status: 'success',
      user_id: 'system',
      details: 'Login via Auth0 Universal Login'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
      action: 'GitHub account connected',
      api: 'Auth0',
      scope_used: 'public_repo,read:user,user:email',
      risk_level: 'low',
      status: 'success',
      user_id: 'system',
      details: 'GitHub social connection linked via Auth0 Token Vault'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
      action: 'Token exchange',
      api: 'Auth0 Token Vault',
      scope_used: 'read:user_idp_tokens',
      risk_level: 'low',
      status: 'success',
      user_id: 'system',
      details: 'GitHub OAuth token retrieved from Auth0 Token Vault identity'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      action: 'List user repositories',
      api: 'GitHub',
      scope_used: 'repo:read',
      risk_level: 'low',
      status: 'success',
      user_id: 'system',
      details: '[Primary Agent] Public repositories listed successfully'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      action: 'List user repositories',
      api: 'GitHub',
      scope_used: 'repo:read',
      risk_level: 'low',
      status: 'success',
      user_id: 'system',
      details: '[Sub-Agent] Public repositories listed successfully'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
      action: 'create issue in repository',
      api: 'GitHub',
      scope_used: 'issues:write',
      risk_level: 'medium',
      status: 'blocked',
      user_id: 'system',
      details: '[Sub-Agent] Scope escalation blocked — action "create_issue" exceeds delegated permissions (repo:read only)'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 19).toISOString(),
      action: 'create issue in repository',
      api: 'GitHub',
      scope_used: 'issues:write',
      risk_level: 'medium',
      status: 'success',
      user_id: 'system',
      details: '[Primary Agent] Issue created successfully'
    },
    {
      timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      action: 'delete repository',
      api: 'GitHub',
      scope_used: 'admin',
      risk_level: 'high',
      status: 'blocked',
      user_id: 'system',
      details: 'Step-up authorization granted but action blocked in demo mode for safety'
    }
  ];

  for (const entry of seedEntries) {
    db.run(
      `INSERT INTO audit_log (timestamp, action, api, scope_used, risk_level, status, user_id, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [entry.timestamp, entry.action, entry.api, entry.scope_used,
       entry.risk_level, entry.status, entry.user_id, entry.details]
    );
  }

  console.log('Database initialized with seed audit entries');
  return db;
}

function logAction({ action, api, scope_used, risk_level, status, user_id, details }) {
  if (!db) throw new Error('Database not initialized');

  db.run(
    `INSERT INTO audit_log (action, api, scope_used, risk_level, status, user_id, details)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [action, api, scope_used, risk_level, status, user_id || 'anonymous', details || null]
  );
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
