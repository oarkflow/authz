"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const documents = new Map();
const workspaceFolders = [];
let buffer = Buffer.alloc(0);

const directives = [
  ["include", "Include another .authz file", "include \"./other.authz\""],
  ["tenant", "Define a tenant", "tenant ${1:id} \"${2:Display Name}\"${3: parent:${4:parent_id}}"],
  ["policy", "Define an ABAC policy", "policy ${1:id} ${2:tenant} ${3|allow,deny|} ${4:read} ${5:document:*} ${6:true} priority:${7:10}"],
  ["role", "Define an RBAC role", "role ${1:id} ${2:tenant} \"${3:Role Name}\" ${4:read:document:*}${5: inherits:${6:parent_role}}"],
  ["acl", "Define an ACL entry", "acl ${1:id} ${2:document:123} ${3:user:alice} ${4:read} ${5|allow,deny|}"],
  ["member", "Assign a role to a subject", "member ${1:user:alice} ${2:role_id}"],
  ["members", "Assign roles to many subjects", "members {\n  ${1:user:alice} [${2:role_id}]\n}"],
  ["engine", "Configure runtime settings", "engine cache_ttl=${1:5000} attr_ttl=${2:10000} batch_size=${3:128} flush_interval=${4:50} workers=${5:8}"],
  ["user", "Define a user", "user ${1:id} ${2:tenant} ${3:user@example.com} \"${4:Full Name}\" status:${5|active,suspended,deactivated|}"],
  ["group", "Define a group", "group ${1:id} ${2:tenant} \"${3:Group Name}\"${4: parent:${5:parent_group}}"],
  ["scope", "Define a scope", "scope ${1:id} ${2:tenant} \"${3:Scope Name}\"${4: parent:${5:parent_scope}}"],
  ["service_account", "Define a service account", "service_account ${1:id} ${2:tenant} \"${3:Service Name}\" client:${4:client_id} roles:${5:role_id} scopes:${6:scope_id}"],
  ["invitation", "Define an invitation", "invitation ${1:id} ${2:tenant} ${3:user@example.com} ${4:role_id} groups:${5:group_id}"],
  ["api_key", "Define an API key", "api_key ${1:id} ${2:tenant} ${3:user_id} ${4:prefix} \"${5:Key Name}\" scopes:${6:scope_id}"],
  ["boundary", "Define a permission boundary", "boundary ${1:id} ${2:tenant} \"${3:Boundary Name}\" ${4:read,write} ${5:document:*}"]
];

const directiveSet = new Set(directives.map(([name]) => name));
const effects = ["allow", "deny"];
const statuses = ["active", "suspended", "deactivated", "pending", "accepted", "expired", "revoked"];
const actions = ["*", "read", "write", "delete", "create", "update", "admin", "share", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const resources = ["*", "document:*", "document:sensitive:*", "project:*", "route:*", "route:GET:/users/*", "route:POST:/admin/*"];
const subjects = ["*", "guest", "user:alice", "group:engineering", "service:worker"];
const fields = [
  "subject.id", "subject.type", "subject.tenant_id", "subject.roles", "subject.groups", "subject.attrs.",
  "resource.id", "resource.type", "resource.tenant_id", "resource.owner_id", "resource.attrs.",
  "env.tenant_id", "env.region", "env.time", "env.ip", "env.extra.", "action"
];
const functions = [
  ["regex(${1:subject.id},${2:^user:})", "Matches a field against a regular expression."],
  ["cidr(${1:10.0.0.0/8})", "Checks env.ip against a CIDR block."],
  ["ip_in_cidr(${1:10.0.0.0/8})", "Alias for cidr."],
  ["time_between(${1:09:00},${2:18:00})", "Checks request time against a HH:MM range."],
  ["range(${1:subject.attrs.score},${2:1},${3:10})", "Checks a numeric field against an inclusive range."]
];
const operators = ["=", "==", "!=", ">=", "@", " in [${1:value}]", " contains any [${1:value}]", " has_any [${1:value}]", " && ", " || ", "true"];
const optionsByDirective = {
  tenant: ["parent:"],
  policy: ["priority:"],
  role: ["inherits:", "owner:"],
  acl: ["expires:"],
  user: ["status:"],
  group: ["parent:", "desc:"],
  scope: ["parent:", "desc:"],
  service_account: ["client:", "roles:", "scopes:", "status:"],
  invitation: ["groups:", "status:", "invited_by:", "expires:"],
  api_key: ["scopes:", "expires:"]
};
const blockFields = {
  tenant: ["name", "parent"],
  policy: ["tenant", "effect", "actions", "resources", "when", "condition", "priority"],
  role: ["tenant", "name", "permissions", "inherits", "owner_actions"],
  acl: ["tenant", "resource", "subject", "actions", "effect", "expires"],
  member: ["roles"],
  engine: ["cache_ttl", "attr_ttl", "batch_size", "flush_interval", "workers"]
};
const required = { include: 2, tenant: 3, policy: 7, role: 5, acl: 6, member: 3, engine: 1, user: 5, group: 4, scope: 4, service_account: 4, invitation: 5, api_key: 6, boundary: 6 };

process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  readMessages();
});

function readMessages() {
  while (true) {
    const sep = buffer.indexOf("\r\n\r\n");
    if (sep === -1) return;
    const header = buffer.slice(0, sep).toString("utf8");
    const match = /Content-Length:\s*(\d+)/i.exec(header);
    if (!match) {
      buffer = buffer.slice(sep + 4);
      continue;
    }
    const length = Number(match[1]);
    const start = sep + 4;
    const end = start + length;
    if (buffer.length < end) return;
    const raw = buffer.slice(start, end).toString("utf8");
    buffer = buffer.slice(end);
    try {
      handle(JSON.parse(raw));
    } catch (err) {
      log(`Failed to parse message: ${err.message}`);
    }
  }
}

function handle(message) {
  if (message.method === "initialize") {
    workspaceFolders.splice(0, workspaceFolders.length, ...((message.params && message.params.workspaceFolders) || []).map((folder) => uriToPath(folder.uri)).filter(Boolean));
    respond(message.id, {
      capabilities: {
        textDocumentSync: 2,
        completionProvider: { triggerCharacters: [" ", ":", "=", ",", ".", "@", "[", "{"] },
        hoverProvider: true,
        definitionProvider: true,
        referencesProvider: true,
        documentSymbolProvider: true,
        documentFormattingProvider: true
      },
      serverInfo: { name: "authz-lsp", version: "0.2.3" }
    });
    return;
  }
  if (message.method === "shutdown") return respond(message.id, null);
  if (message.method === "exit") return process.exit(0);
  if (message.method === "textDocument/didOpen") return setDocument(message.params.textDocument.uri, message.params.textDocument.text);
  if (message.method === "textDocument/didChange") return setDocument(message.params.textDocument.uri, message.params.contentChanges.at(-1).text);
  if (message.method === "textDocument/didClose") return documents.delete(message.params.textDocument.uri);
  if (message.method === "textDocument/completion") return respond(message.id, completion(message.params));
  if (message.method === "textDocument/hover") return respond(message.id, hover(message.params));
  if (message.method === "textDocument/definition") return respond(message.id, definition(message.params));
  if (message.method === "textDocument/references") return respond(message.id, references(message.params));
  if (message.method === "textDocument/documentSymbol") return respond(message.id, symbols(message.params));
  if (message.method === "textDocument/formatting") return respond(message.id, formatting(message.params));
  if (message.id !== undefined) respond(message.id, null);
}

function setDocument(uri, text) {
  documents.set(uri, text || "");
  publishDiagnostics(uri);
}

function publishDiagnostics(uri) {
  send("textDocument/publishDiagnostics", { uri, diagnostics: validate(getText(uri), uri) });
}

function completion(params) {
  const text = getText(params.textDocument.uri);
  const lines = splitLines(text);
  const line = lines[params.position.line] || "";
  const before = line.slice(0, params.position.character);
  const parsed = parseLine(before);
  const index = buildIndex();
  const block = blockContext(lines, params.position.line);
  if (block && !isBlockHeader(parsed.tokens)) {
    const field = blockField(lines, block, params.position.line);
    const values = blockValueCompletions(block.directive, field || parsed.tokens[0], index);
    return { isIncomplete: false, items: values };
  }
  if (parsed.tokens.length === 0 || (parsed.tokens.length === 1 && !before.endsWith(" "))) {
    return items(directives.map(([label, detail, insertText]) => ({ label, detail, insertText, kind: 14, insertTextFormat: 2 })));
  }
  const directive = parsed.tokens[0];
  const tokenIndex = parsed.tokens.length - (before.endsWith(" ") ? 0 : 1);
  if (directive === "engine") return items(["cache_ttl=", "attr_ttl=", "batch_size=", "flush_interval=", "workers="].map((label) => ({ label, kind: 10 })));
  if (directive === "include") return items([{ label: "\"./*.authz\"", kind: 17 }]);
  if (directive === "policy") {
    if (tokenIndex === 2) return idItems(index.tenants, "Tenant ID");
    if (tokenIndex === 3) return enumItems(effects);
    if (tokenIndex === 4) return valueItems([...actions, ...index.actions]);
    if (tokenIndex === 5) return valueItems([...resources, ...index.resources]);
    if (tokenIndex >= 6) return conditionItems();
  }
  if (directive === "role") {
    if (tokenIndex === 2) return idItems(index.tenants, "Tenant ID");
    if (tokenIndex === 4) return valueItems(["*:*", "read:document:*", "write:document:*", "GET:route:GET:/admin/*"]);
  }
  if (directive === "acl") {
    if (tokenIndex === 2) return valueItems([...resources, ...index.resources]);
    if (tokenIndex === 3) return idItems([...subjects, ...index.subjects], "Subject");
    if (tokenIndex === 4) return valueItems([...actions, ...index.actions]);
    if (tokenIndex === 5) return enumItems(effects);
  }
  if (directive === "member") {
    if (tokenIndex === 1) return idItems([...subjects, ...index.subjects], "Subject");
    if (tokenIndex === 2) return idItems(index.roles, "Role ID");
  }
  if (["user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive) && tokenIndex === 2) return idItems(index.tenants, "Tenant ID");
  const opts = optionsByDirective[directive] || [];
  return items(opts.map((label) => ({ label, kind: 10 })));
}

function blockValueCompletions(directive, field, index) {
  if (!field || field === "{") return items((blockFields[directive] || []).map((label) => ({ label, kind: 10 })));
  if (field === "tenant") return idItems(index.tenants, "Tenant ID");
  if (field === "effect") return enumItems(effects);
  if (field === "actions" || field === "owner_actions") return valueItems([...actions, ...index.actions]);
  if (field === "resources" || field === "resource") return valueItems([...resources, ...index.resources]);
  if (field === "subject") return idItems([...subjects, ...index.subjects], "Subject");
  if (field === "permissions") return valueItems(["*:*", "read:document:*", "write:document:*", "GET:route:GET:/admin/*"]);
  if (field === "inherits" || field === "roles") return idItems(index.roles, "Role ID");
  if (field === "when" || field === "condition") return conditionItems();
  return items([]);
}

function conditionItems() {
  return items([
    ...fields.map((label) => ({ label, kind: 5, detail: "Condition field" })),
    ...operators.map((label) => ({ label: label.replace(/\$\{\d+:([^}]+)\}/g, "$1"), insertText: label, insertTextFormat: label.includes("${") ? 2 : 1, kind: 24 })),
    ...functions.map(([insertText, detail]) => ({ label: insertText.replace(/\$\{\d+:([^}]+)\}/g, "$1"), insertText, insertTextFormat: 2, detail, kind: 3 }))
  ]);
}

function hover(params) {
  const text = getText(params.textDocument.uri);
  const line = splitLines(text)[params.position.line] || "";
  const parsed = parseLine(line);
  const token = tokenAt(parsed, params.position.character);
  if (!token) return null;
  const word = token.value;
  const directive = parsed.tokens[0];
  const tokenIndex = parsed.tokenInfos.indexOf(token);
  const directiveDoc = directives.find(([name]) => name === word);
  if (directiveDoc) return markdown(`**${word}**\n\n${directiveDoc[1]}\n\nSyntax: \`${directiveDoc[2].replace(/\$\{\d+:([^}]+)\}/g, "$1")}\``);
  if (fields.includes(word) || word.startsWith("subject.attrs.") || word.startsWith("resource.attrs.") || word.startsWith("env.extra.")) return markdown(`**${word}**\n\nRuntime authorization field available in policy conditions.`);
  const fn = functions.find(([snippet]) => snippet.startsWith(`${word}(`));
  if (fn) return markdown(`**${word}**\n\n${fn[1]}`);
  if (effects.includes(word)) return markdown(`**Effect \`${word}\`**\n\n${word === "deny" ? "Deny matches override allows." : "Allow grants access when action, resource, and condition match."}`);
  if (directive === "policy" && tokenIndex === 6) return markdown(`**Policy condition**\n\nABAC predicate evaluated against subject, resource, action, and environment.\n\n\`${word}\``);
  if (isPermission(word)) return markdown(`**Permission \`${word}\`**\n\nRole permission in \`action:resource\` form. Explicit denies still override RBAC grants.`);
  if (word.includes(":")) return markdown(`**AuthZ token \`${word}\`**\n\nResource, subject, option, or permission-style token depending on context.`);
  return markdown(`**${word}**\n\nAuthZ DSL symbol.`);
}

function definition(params) {
  const target = targetAt(params);
  if (!target) return null;
  const defs = buildIndex().definitions.get(target.key) || [];
  return defs.length ? defs : null;
}

function references(params) {
  const target = targetAt(params);
  if (!target) return null;
  const index = buildIndex();
  const defs = index.definitions.get(target.key) || [];
  const refs = index.references.filter((ref) => ref.key === target.key).map((ref) => ref.location);
  return [...defs, ...refs];
}

function targetAt(params) {
  const text = getText(params.textDocument.uri);
  const line = splitLines(text)[params.position.line] || "";
  const parsed = parseLine(line);
  const token = tokenAt(parsed, params.position.character);
  if (!token) return null;
  const directive = parsed.tokens[0];
  const idx = parsed.tokenInfos.indexOf(token);
  if (idx === 1 && ["tenant", "role", "user", "group", "scope", "service_account"].includes(directive)) return { key: definitionKey(directive, token.value) };
  if (["policy", "role"].includes(directive) && idx === 2) return { key: token.value };
  if (directive === "member" && idx === 2) return { key: `role:${token.value}` };
  if (directive === "api_key" && idx === 3) return { key: `user:${token.value}` };
  return { key: token.value };
}

function symbols(params) {
  return buildTextIndex(getText(params.textDocument.uri), params.textDocument.uri).entries.map((entry) => ({
    name: entry.id,
    detail: entry.directive,
    kind: symbolKind(entry.directive),
    range: entry.range,
    selectionRange: entry.selectionRange
  }));
}

function formatting(params) {
  const text = getText(params.textDocument.uri);
  const formatted = splitLines(text).map((line) => /^\s*#/.test(line) || line.trim() === "" ? line.trimEnd() : line.replace(/\s+#/, " #").trim()).join("\n");
  return [{ range: rangeForText(text), newText: formatted.endsWith("\n") ? formatted : `${formatted}\n` }];
}

function validate(text, uri) {
  const diagnostics = [];
  const lines = splitLines(text);
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLine(lines[i]);
    if (parsed.error) {
      diagnostics.push(diagnostic(i, 0, lines[i].length, parsed.error, 1));
      continue;
    }
    const tokens = parsed.tokens;
    if (!tokens.length) continue;
    if (!directiveSet.has(tokens[0]) && tokens[0] !== "}" && tokens[0] !== "]") {
      diagnostics.push(diagnostic(i, 0, tokens[0].length, `Unknown AuthZ directive "${tokens[0]}".`, 1));
      continue;
    }
    if (isBlockHeader(tokens)) {
      const block = collectBlock(lines, i);
      diagnostics.push(...validateBlock(lines, i, block.end, tokens));
      i = block.end;
      continue;
    }
    const need = required[tokens[0]];
    if (need && tokens.length < need) diagnostics.push(diagnostic(i, 0, lines[i].length, `${tokens[0]} requires ${need - 1} argument(s).`, 2));
    if ((tokens[0] === "policy" && tokens[3] && !effects.includes(tokens[3])) || (tokens[0] === "acl" && tokens[5] && !effects.includes(tokens[5]))) {
      const effect = tokens[0] === "policy" ? tokens[3] : tokens[5];
      diagnostics.push(tokenDiagnostic(lines[i], i, effect, "Effect must be allow or deny.", 1));
    }
    for (const token of tokens) {
      if (token.includes(",,")) diagnostics.push(tokenDiagnostic(lines[i], i, token, "Lists cannot contain empty items.", 1));
      if (token.startsWith("expires:") && token.length > 8 && Number.isNaN(Date.parse(token.slice(8)))) diagnostics.push(tokenDiagnostic(lines[i], i, token, "expires must be an RFC3339 timestamp.", 1));
    }
  }
  const cli = process.env.AUTHZ_LSP_CLI === "1" ? validateWithCLI(text, uri) : null;
  return cli ? diagnostics.concat(cli) : diagnostics;
}

function validateBlock(lines, start, end, header) {
  const diagnostics = [];
  const directive = header[0];
  const allowed = new Set(blockFields[directive] || []);
  const seen = new Set();
  let activeList = "";
  let activeNested = "";
  for (let i = start + 1; i <= end; i++) {
    const parsed = parseLine(lines[i]);
    const tokens = parsed.tokens;
    if (!tokens.length) continue;
    if (tokens.length === 1 && tokens[0] === "]") {
      activeList = "";
      continue;
    }
    if (tokens.length === 1 && tokens[0] === "}") {
      activeNested = "";
      continue;
    }
    if (directive === "members") continue;
    const field = activeList || activeNested || tokens[0];
    if (!activeList && !activeNested) {
      seen.add(field);
      if (allowed.size && !allowed.has(field)) diagnostics.push(tokenDiagnostic(lines[i], i, field, `Unknown ${directive} block field "${field}".`, 1));
      if (tokens[1] === "[") activeList = field;
      if (tokens[1] === "{") activeNested = field;
    }
    if (field === "effect" && tokens[1] && !effects.includes(tokens[1])) diagnostics.push(tokenDiagnostic(lines[i], i, tokens[1], "Effect must be allow or deny.", 1));
  }
  const requiredFields = { policy: ["tenant", "effect", "actions", "resources"], role: ["tenant", "permissions"], acl: ["resource", "subject", "actions", "effect"], member: ["roles"] }[directive] || [];
  for (const field of requiredFields) if (!seen.has(field)) diagnostics.push(diagnostic(start, 0, lines[start].length, `${directive} block is missing required field "${field}".`, 2));
  return diagnostics;
}

function validateWithCLI(text, uri) {
  const file = uriToPath(uri);
  if (!file || !fs.existsSync(file)) return null;
  const root = workspaceFolders.find((folder) => fs.existsSync(path.join(folder, "cmd", "authz-config", "main.go")));
  if (!root) return null;
  try {
    const result = cp.spawnSync("go", ["run", "./cmd/authz-config", "validate", file], { cwd: root, encoding: "utf8", timeout: 10000 });
    if (result.status === 0) return null;
    const output = `${result.stdout}\n${result.stderr}`.trim();
    const match = /line\s+(\d+):\s*(.*)/i.exec(output);
    const line = match ? Math.max(0, Number(match[1]) - 1) : 0;
    return [diagnostic(line, 0, Math.max(1, (splitLines(text)[line] || "").length), match ? match[2] : output || "authz-config validation failed", 1)];
  } catch {
    return null;
  }
}

function buildIndex() {
  const index = emptyIndex();
  for (const [uri, text] of documents) mergeIndex(index, buildTextIndex(text, uri));
  for (const root of workspaceFolders) {
    for (const file of walk(root).filter((name) => /\.(authz|dsl)$/i.test(name))) {
      const uri = pathToUri(file);
      if (documents.has(uri)) continue;
      try {
        mergeIndex(index, buildTextIndex(fs.readFileSync(file, "utf8"), uri));
      } catch {}
    }
  }
  dedupeIndex(index);
  return index;
}

function buildTextIndex(text, uri) {
  const index = emptyIndex();
  const lines = splitLines(text);
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLine(lines[i]);
    const tokens = parsed.tokens;
    if (tokens.length < 2) continue;
    if (isBlockHeader(tokens)) {
      const block = collectBlock(lines, i);
      addEntry(index, tokens[0], tokens[1], uri, i, block.end, parsed.tokenInfos[1]);
      i = block.end;
      continue;
    }
    addEntry(index, tokens[0], tokens[1], uri, i, i, parsed.tokenInfos[1]);
    collectRefs(index, uri, i, parsed);
  }
  return index;
}

function addEntry(index, directive, id, uri, startLine, endLine, tokenInfo) {
  if (!["tenant", "policy", "role", "acl", "user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive)) return;
  const clean = unquote(id);
  const selectionRange = { start: { line: startLine, character: tokenInfo ? tokenInfo.start : 0 }, end: { line: startLine, character: tokenInfo ? tokenInfo.end : clean.length } };
  const range = { start: { line: startLine, character: 0 }, end: { line: endLine, character: Number.MAX_SAFE_INTEGER } };
  index.entries.push({ directive, id: clean, range, selectionRange });
  const collection = directive === "service_account" ? "serviceAccounts" : directive === "api_key" ? "apiKeys" : directive === "boundary" ? "boundaries" : `${directive}s`;
  if (index[collection]) index[collection].push(clean);
  if (directive === "user") index.subjects.push(`user:${clean}`);
  if (directive === "group") index.subjects.push(`group:${clean}`);
  if (directive === "service_account") index.subjects.push(`service:${clean}`);
  for (const key of [clean, definitionKey(directive, clean)]) {
    if (!key) continue;
    if (!index.definitions.has(key)) index.definitions.set(key, []);
    index.definitions.get(key).push({ uri, range: selectionRange });
  }
}

function collectRefs(index, uri, line, parsed) {
  const directive = parsed.tokens[0];
  for (let i = 1; i < parsed.tokens.length; i++) {
    const token = parsed.tokenInfos[i];
    const keys = [];
    if (["policy", "role"].includes(directive) && i === 2) keys.push(token.value);
    if (directive === "member" && i === 2) keys.push(`role:${token.value}`);
    if (directive === "api_key" && i === 3) keys.push(`user:${token.value}`);
    for (const key of keys) index.references.push({ key, location: { uri, range: { start: { line, character: token.start }, end: { line, character: token.end } } } });
  }
}

function emptyIndex() {
  return { tenants: [], policies: [], roles: [], acls: [], users: [], groups: [], scopes: [], serviceAccounts: [], invitations: [], apiKeys: [], boundaries: [], subjects: [], actions: [], resources: [], definitions: new Map(), references: [], entries: [] };
}

function mergeIndex(target, source) {
  for (const key of ["tenants", "policies", "roles", "acls", "users", "groups", "scopes", "serviceAccounts", "invitations", "apiKeys", "boundaries", "subjects", "actions", "resources", "references", "entries"]) target[key].push(...source[key]);
  for (const [key, value] of source.definitions) {
    if (!target.definitions.has(key)) target.definitions.set(key, []);
    target.definitions.get(key).push(...value);
  }
}

function dedupeIndex(index) {
  for (const key of ["tenants", "policies", "roles", "acls", "users", "groups", "scopes", "serviceAccounts", "invitations", "apiKeys", "boundaries", "subjects", "actions", "resources"]) index[key] = [...new Set(index[key].filter(Boolean))];
}

function definitionKey(directive, id) {
  if (directive === "tenant") return id;
  if (directive === "service_account") return `service:${id}`;
  if (["role", "user", "group", "scope", "policy", "acl", "invitation", "api_key", "boundary"].includes(directive)) return `${directive}:${id}`;
  return id;
}

function parseLine(line) {
  const tokens = [];
  const tokenInfos = [];
  let token = "";
  let quote = "";
  let start = -1;
  let end = -1;
  const push = () => {
    if (!token) return;
    tokens.push(token);
    tokenInfos.push({ value: token, start, end: end >= start ? end : start + token.length });
    token = "";
    start = -1;
    end = -1;
  };
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (!quote && ch === "#") break;
    if (!quote && /\s/.test(ch)) {
      push();
      continue;
    }
    if ((ch === "\"" || ch === "'" || ch === "`") && (!quote || quote === ch)) {
      if (!quote && start === -1) start = i + 1;
      if (quote) {
        end = i;
        quote = "";
      } else {
        quote = ch;
      }
      continue;
    }
    if (start === -1) start = i;
    token += ch;
    end = i + 1;
  }
  if (quote) return { tokens, tokenInfos, error: "Unterminated quoted string." };
  push();
  return { tokens, tokenInfos };
}

function tokenAt(parsed, character) {
  return parsed.tokenInfos.find((token) => character >= token.start && character <= token.end);
}

function isBlockHeader(tokens) {
  return tokens.length >= 2 && tokens.at(-1) === "{" && ["tenant", "policy", "role", "acl", "member", "members", "engine"].includes(tokens[0]);
}

function collectBlock(lines, start) {
  let depth = braceDelta(lines[start]);
  let end = start;
  for (let i = start + 1; i < lines.length; i++) {
    depth += braceDelta(lines[i]);
    end = i;
    if (depth <= 0) break;
  }
  return { end };
}

function braceDelta(line) {
  let quote = "";
  let delta = 0;
  for (const ch of line) {
    if (!quote && ch === "#") break;
    if ((ch === "\"" || ch === "'" || ch === "`") && (!quote || quote === ch)) {
      quote = quote ? "" : ch;
      continue;
    }
    if (quote) continue;
    if (ch === "{") delta++;
    if (ch === "}") delta--;
  }
  return delta;
}

function blockContext(lines, lineNo) {
  let depth = 0;
  let active = null;
  for (let i = 0; i < lineNo; i++) {
    const parsed = parseLine(lines[i]);
    if (isBlockHeader(parsed.tokens)) active = { directive: parsed.tokens[0], start: i };
    depth += braceDelta(lines[i]);
    if (depth <= 0) active = null;
  }
  return active;
}

function blockField(lines, block, lineNo) {
  let active = "";
  for (let i = block.start + 1; i <= lineNo; i++) {
    const tokens = parseLine(lines[i]).tokens;
    if (!tokens.length) continue;
    if (tokens.length === 1 && (tokens[0] === "]" || tokens[0] === "}")) {
      active = "";
      continue;
    }
    if (tokens[1] === "[" || tokens[1] === "{") active = tokens[0];
    if (i === lineNo) return active || tokens[0] || "";
  }
  return "";
}

function items(values) {
  return { isIncomplete: false, items: values };
}

function idItems(values, detail) {
  return items([...new Set(values.filter(Boolean))].map((label) => ({ label, detail, kind: 18 })));
}

function valueItems(values) {
  return items([...new Set(values.filter(Boolean))].map((label) => ({ label, kind: 12 })));
}

function enumItems(values) {
  return items(values.map((label) => ({ label, kind: 20 })));
}

function markdown(value) {
  return { contents: { kind: "markdown", value } };
}

function diagnostic(line, start, end, message, severity) {
  return { range: { start: { line, character: start }, end: { line, character: end } }, message, severity, source: "authz-lsp" };
}

function tokenDiagnostic(lineText, line, token, message, severity) {
  const start = Math.max(0, lineText.indexOf(token));
  return diagnostic(line, start, start + token.length, message, severity);
}

function rangeForText(text) {
  const lines = splitLines(text);
  return { start: { line: 0, character: 0 }, end: { line: Math.max(0, lines.length - 1), character: (lines.at(-1) || "").length } };
}

function isPermission(value) {
  return value === "*:*" || /^[^:,\s]+:.+$/.test(value);
}

function splitLines(text) {
  return String(text || "").split(/\r?\n/);
}

function getText(uri) {
  if (documents.has(uri)) return documents.get(uri);
  const file = uriToPath(uri);
  if (file && fs.existsSync(file)) return fs.readFileSync(file, "utf8");
  return "";
}

function unquote(value) {
  return String(value || "").replace(/^["'`]|["'`]$/g, "");
}

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else out.push(full);
    }
  }
  return out;
}

function uriToPath(uri) {
  if (!uri || !uri.startsWith("file://")) return "";
  return decodeURIComponent(uri.replace(/^file:\/\//, ""));
}

function pathToUri(file) {
  return `file://${encodeURI(file)}`;
}

function respond(id, result) {
  write({ jsonrpc: "2.0", id, result });
}

function send(method, params) {
  write({ jsonrpc: "2.0", method, params });
}

function write(message) {
  const json = JSON.stringify(message);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json, "utf8")}\r\n\r\n${json}`);
}

function log(message) {
  send("window/logMessage", { type: 3, message });
}
