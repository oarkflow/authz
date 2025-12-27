-- roles table
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  name TEXT,
  permissions_json TEXT,
  owner_allowed_actions_json TEXT,
  inherits_json TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- policies table
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  effect TEXT,
  actions_json TEXT,
  resources_json TEXT,
  condition_text TEXT,
  priority INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  version INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
);

-- policy history
CREATE TABLE IF NOT EXISTS policy_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT,
  snapshot_json TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- role membership (assign roles to subjects)
CREATE TABLE IF NOT EXISTS role_members (
  subject_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  PRIMARY KEY(subject_id, role_id)
);

-- ACLs (resource-specific overrides)
CREATE TABLE IF NOT EXISTS acls (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  actions_json TEXT,
  effect TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- audit log for decisions
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  tenant_id TEXT,
  subject_id TEXT,
  action TEXT,
  resource TEXT,
  allowed INTEGER,
  matched_by TEXT,
  reason TEXT,
  trace_json TEXT,
  metadata_json TEXT
);
