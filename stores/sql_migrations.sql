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
  tenant_id TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- tenants table
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT,
  parent_id TEXT,
  attrs_json TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
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

-- invitations
CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role_ids_json TEXT,
  group_ids_json TEXT,
  token_hash TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  invited_by TEXT,
  message TEXT,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  accepted_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_invitations_tenant ON invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token_hash);

-- service accounts
CREATE TABLE IF NOT EXISTS service_accounts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  client_id TEXT NOT NULL UNIQUE,
  client_secret TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  roles_json TEXT,
  scopes_json TEXT,
  created_by TEXT,
  last_used_at DATETIME,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sa_client_id ON service_accounts(client_id);
CREATE INDEX IF NOT EXISTS idx_sa_tenant_id ON service_accounts(tenant_id);

-- users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  password_hash TEXT,
  status TEXT DEFAULT 'active',
  email_verified INTEGER DEFAULT 0,
  mfa_enabled INTEGER DEFAULT 0,
  mfa_secret TEXT,
  attrs_json TEXT,
  last_login_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- groups table
CREATE TABLE IF NOT EXISTS groups_ (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  parent_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_groups_tenant_id ON groups_(tenant_id);

-- group membership
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY(group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

-- group-role mapping
CREATE TABLE IF NOT EXISTS group_roles (
  group_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  PRIMARY KEY(group_id, role_id)
);

-- scopes table
CREATE TABLE IF NOT EXISTS scopes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  parent_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scopes_tenant_name ON scopes(tenant_id, name);

-- role-scope mappings
CREATE TABLE IF NOT EXISTS role_scopes (
  role_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  PRIMARY KEY(role_id, scope_id)
);

-- events log
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL,
  actor_id TEXT,
  target_id TEXT,
  data_json TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

-- webhooks
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT,
  events_json TEXT,
  enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

-- webhook deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  status_code INTEGER,
  success INTEGER,
  error TEXT,
  attempts INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- permission boundaries
CREATE TABLE IF NOT EXISTS permission_boundaries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  max_actions_json TEXT,
  max_resources_json TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- user to boundary mapping
CREATE TABLE IF NOT EXISTS user_boundaries (
  user_id TEXT PRIMARY KEY,
  boundary_id TEXT NOT NULL
);

-- sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  refresh_token TEXT,
  ip_address TEXT,
  user_agent TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- api keys
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT,
  prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  scopes_json TEXT,
  expires_at DATETIME,
  last_used DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_apikeys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_apikeys_user ON api_keys(user_id);
