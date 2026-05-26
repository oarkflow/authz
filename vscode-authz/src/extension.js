"use strict";

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const language = { language: "authz", scheme: "file" };
let authzLspClient;

const directives = [
  ["include", "include \"./other.authz\"", "Include another .authz file"],
  ["tenant", "tenant id \"Display Name\" [parent:parent_id] or tenant id { name \"Display Name\" }", "Define a tenant"],
  ["policy", "policy id tenant allow actions resources condition [priority:n] or policy id { ... }", "Define an ABAC policy"],
  ["role", "role id tenant \"Name\" perms [inherits:roles] [owner:actions] or role id { ... }", "Define an RBAC role"],
  ["acl", "acl id resource subject actions allow [expires:time] or acl id { ... }", "Define an ACL entry"],
  ["member", "member subject role or member subject { roles [...] }", "Assign a role to a subject"],
  ["members", "members { subject [roles] }", "Assign roles to many subjects"],
  ["engine", "engine cache_ttl=ms attr_ttl=ms batch_size=n flush_interval=ms workers=n or engine { ... }", "Configure engine runtime"],
  ["user", "user id tenant email \"Name\" [status:status]", "Define a user"],
  ["group", "group id tenant \"Name\" [parent:group] [desc:text]", "Define a group"],
  ["scope", "scope id tenant \"Name\" [parent:scope] [desc:text]", "Define a scope"],
  ["service_account", "service_account id tenant \"Name\" [client:id] [roles:roles] [scopes:scopes] [status:status]", "Define a service account"],
  ["invitation", "invitation id tenant email roles [groups:groups] [status:status] [invited_by:user] [expires:time]", "Define an invitation"],
  ["api_key", "api_key id tenant user prefix \"Name\" [scopes:scopes] [expires:time]", "Define an API key"],
  ["boundary", "boundary id tenant \"Name\" actions resources", "Define a permission boundary"]
];

const optionsByDirective = {
  tenant: [["parent:", "Parent tenant ID"]],
  policy: [["priority:", "Policy priority, higher values win"]],
  role: [["inherits:", "Comma-separated inherited role IDs"], ["owner:", "Comma-separated owner actions"]],
  acl: [["expires:", "RFC3339 expiration timestamp"]],
  user: [["status:", "active, suspended, or deactivated"]],
  group: [["parent:", "Parent group ID"], ["desc:", "Description text"]],
  scope: [["parent:", "Parent scope ID"], ["desc:", "Description text"]],
  service_account: [["client:", "Client ID"], ["roles:", "Comma-separated role IDs"], ["scopes:", "Comma-separated scope IDs"], ["status:", "active, suspended, or deactivated"]],
  invitation: [["groups:", "Comma-separated group IDs"], ["status:", "pending, accepted, expired, or revoked"], ["invited_by:", "Inviting user ID"], ["expires:", "RFC3339 expiration timestamp"]],
  api_key: [["scopes:", "Comma-separated scope IDs"], ["expires:", "RFC3339 expiration timestamp"]]
};

const engineOptions = [
  ["cache_ttl=", "Decision cache TTL in milliseconds"],
  ["attr_ttl=", "Attribute cache TTL in milliseconds"],
  ["batch_size=", "Audit batch size"],
  ["flush_interval=", "Audit flush interval in milliseconds"],
  ["workers=", "Batch worker count"]
];

const effects = ["allow", "deny"];
const userStatuses = ["active", "suspended", "deactivated"];
const inviteStatuses = ["pending", "accepted", "expired", "revoked"];
const actions = ["*", "read", "write", "delete", "create", "update", "admin", "share", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const resources = ["*", "document:*", "document:sensitive:*", "project:*", "route:*", "route:GET:/users/*", "route:POST:/admin/*"];
const subjects = ["*", "guest", "user:alice", "group:engineering", "service:worker"];
const conditionFields = [
  "subject.id",
  "subject.type",
  "subject.tenant_id",
  "subject.roles",
  "subject.groups",
  "subject.attrs.",
  "resource.id",
  "resource.type",
  "resource.tenant_id",
  "resource.owner_id",
  "resource.attrs.",
  "env.tenant_id",
  "env.region",
  "env.time",
  "env.ip",
  "env.extra.",
  "action"
];
const conditionFunctions = [
  ["regex(${1:subject.id},${2:^user:})", "regex(field, pattern)"],
  ["cidr(${1:10.0.0.0/8})", "cidr(cidrBlock), checked against env.ip"],
  ["ip_in_cidr(${1:10.0.0.0/8})", "Alias for cidr"],
  ["time_between(${1:09:00},${2:18:00})", "time_between(start, end)"],
  ["range(${1:subject.attrs.score},${2:1},${3:10})", "range(field, min, max)"]
];
const conditionOperators = ["=", "==", "!=", ">=", "@", " in [${1:value}]", " contains any [${1:value}]", " has_any [${1:value}]", " has [${1:value}]", " && ", " || ", " AND ", " OR ", "(", ")", "true"];
const blockDirectiveNames = new Set(["tenant", "policy", "role", "acl", "member", "members", "engine"]);
const blockFieldsByDirective = {
  tenant: ["name", "parent"],
  policy: ["tenant", "effect", "actions", "resources", "when", "priority"],
  role: ["tenant", "name", "permissions", "inherits", "owner_actions"],
  acl: ["tenant", "resource", "subject", "actions", "effect", "expires"],
  member: ["roles"],
  engine: ["cache_ttl", "attr_ttl", "batch_size", "flush_interval", "workers"]
};
const requiredBlockFields = {
  tenant: ["name"],
  policy: ["tenant", "effect", "actions", "resources"],
  role: ["tenant", "permissions"],
  acl: ["resource", "subject", "actions", "effect"],
  member: ["roles"]
};

const directiveDocs = new Map(directives.map(([name, syntax, description]) => [name, { syntax, description }]));
const functionDocs = new Map([
  ["regex", "Matches a field value against a regular expression: regex(subject.id,^user:)"],
  ["cidr", "Checks env.ip against a CIDR block: cidr(10.0.0.0/8)"],
  ["ip_in_cidr", "Alias for cidr."],
  ["time_between", "Checks the environment time against a HH:MM range."],
  ["range", "Checks a numeric field inside an inclusive range."]
]);

const explanationRegistry = {
  options: new Map([
    ["parent:", {
      title: "parent:",
      summary: "Links this tenant, group, or scope to a parent entry.",
      runtime: "For tenants, the engine records a child -> parent hierarchy. Tenant checks can allow ancestor/cross-tenant relationships where the engine supports them.",
      example: "`tenant team1 \"Backend Team\" parent:org1` makes `org1` the parent of `team1`."
    }],
    ["priority:", {
      title: "priority:",
      summary: "Sets policy ordering. Higher priority policies are considered before lower-priority policies.",
      runtime: "Deny decisions still take precedence over allow decisions during authorization; priority mainly orders policies within the same effect path.",
      example: "`priority:100` makes a policy more important than `priority:10`."
    }],
    ["inherits:", {
      title: "inherits:",
      summary: "Adds permissions from one or more parent roles to this role.",
      runtime: "Role inheritance is resolved recursively and cycle-protected when RBAC permissions are checked.",
      example: "`role team-lead team1 \"Team Lead\" *:project:* inherits:editor` includes `editor` permissions."
    }],
    ["owner:", {
      title: "owner:",
      summary: "Lists actions an owner role may perform across descendant tenant/resource ownership checks.",
      runtime: "Owner-scoped checks can allow these actions when the subject is recognized as an owner by the engine.",
      example: "`owner:read,write,delete` permits owner-style access for those actions."
    }],
    ["expires:", {
      title: "expires:",
      summary: "Adds an RFC3339 expiration timestamp.",
      runtime: "Expired ACLs/invitations should no longer be treated as active access grants.",
      example: "`expires:2026-12-31T23:59:59Z`."
    }],
    ["status:", {
      title: "status:",
      summary: "Sets lifecycle state for users, service accounts, or invitations.",
      runtime: "Status is parsed into IAM config and can be enforced by the surrounding identity/auth flow.",
      example: "`status:active`, `status:suspended`, `status:pending`."
    }],
    ["roles:", {
      title: "roles:",
      summary: "Assigns role IDs to a service account or invitation.",
      runtime: "Those roles become part of the IAM object and may later feed RBAC membership/assignment workflows.",
      example: "`roles:admin,viewer`."
    }],
    ["scopes:", {
      title: "scopes:",
      summary: "Assigns scope IDs to a service account or API key.",
      runtime: "Scopes constrain or describe API/key capability in IAM-aware integrations.",
      example: "`scopes:billing.read,users.write`."
    }],
    ["groups:", {
      title: "groups:",
      summary: "Assigns invitation recipients to group IDs.",
      runtime: "Groups can later participate in ACLs such as `group:engineering`.",
      example: "`groups:engineering,ops`."
    }],
    ["invited_by:", {
      title: "invited_by:",
      summary: "Records which user created an invitation.",
      runtime: "Useful for audit trails and invitation governance.",
      example: "`invited_by:alice`."
    }],
    ["client:", {
      title: "client:",
      summary: "Sets the external client identifier for a service account.",
      runtime: "This is stored with the service account and can be used by authn/integration layers.",
      example: "`client:worker-prod`."
    }],
    ["desc:", {
      title: "desc:",
      summary: "Adds a description to a group or scope.",
      runtime: "Metadata only; it does not directly grant or deny access.",
      example: "`desc:\"Backend operators\"`."
    }]
  ]),
  engine: new Map([
    ["cache_ttl=", ["Decision cache TTL", "How long authorization decisions stay cached, in milliseconds.", "`cache_ttl=5000` caches decisions for five seconds."]],
    ["attr_ttl=", ["Attribute cache TTL", "How long fetched subject attributes stay cached, in milliseconds.", "`attr_ttl=10000` caches attributes for ten seconds."]],
    ["batch_size=", ["Audit batch size", "How many audit events to buffer before flushing.", "`batch_size=128`."]],
    ["flush_interval=", ["Audit flush interval", "How frequently audit events are flushed, in milliseconds.", "`flush_interval=50`."]],
    ["workers=", ["Batch workers", "Number of workers used for batch authorization/audit work.", "`workers=8`."]]
  ]),
  fields: new Map([
    ["subject.id", ["subject.id", "The runtime subject identifier.", "Compared against `Subject.ID`, for example `user:alice`."]],
    ["subject.type", ["subject.type", "The runtime subject type.", "`subject.type=user` matches a subject whose `Type` is `user`."]],
    ["subject.tenant_id", ["subject.tenant_id", "The tenant attached to the runtime subject.", "Useful for tenant-aware policies."]],
    ["subject.roles", ["subject.roles", "The runtime subject role list.", "`subject.roles@admin,superadmin` matches if any listed role is present."]],
    ["subject.groups", ["subject.groups", "The runtime subject group list.", "Can be used for group-based ABAC conditions."]],
    ["subject.attrs.", ["subject.attrs.<key>", "Custom subject attributes.", "`subject.attrs.clearance!=high` checks an attribute named `clearance`."]],
    ["resource.id", ["resource.id", "The runtime resource identifier.", "For a document resource this may be `123`."]],
    ["resource.type", ["resource.type", "The runtime resource type.", "`document:*` matches resources whose type is `document`."]],
    ["resource.tenant_id", ["resource.tenant_id", "The tenant attached to the runtime resource.", "Used for tenant isolation checks."]],
    ["resource.owner_id", ["resource.owner_id", "The owner recorded on the runtime resource.", "`resource.owner_id=subject.id` grants owner-only access when IDs match."]],
    ["resource.attrs.", ["resource.attrs.<key>", "Custom resource attributes.", "`resource.attrs.region=us` checks a resource attribute."]],
    ["env.tenant_id", ["env.tenant_id", "The tenant in the authorization environment.", "Usually the tenant being evaluated."]],
    ["env.region", ["env.region", "The request/environment region.", "Useful for geo or deployment rules."]],
    ["env.time", ["env.time", "The request time.", "Use with time-aware conditions or helpers."]],
    ["env.ip", ["env.ip", "The request IP address.", "Used by `cidr(...)` / `ip_in_cidr(...)`."]],
    ["env.extra.", ["env.extra.<key>", "Custom environment attributes.", "Use for request-scoped metadata."]],
    ["action", ["action", "The runtime action being authorized.", "For HTTP middleware this may be `GET`, `POST`, etc."]]
  ]),
  functions: new Map([
    ["regex", ["regex(field, pattern)", "Matches a field value against a regular expression.", "`regex(subject.id,^user:)` matches user-style subject IDs."]],
    ["cidr", ["cidr(cidr)", "Checks the request IP against a CIDR block.", "`cidr(10.0.0.0/8)` matches private 10.x addresses via `env.ip`."]],
    ["ip_in_cidr", ["ip_in_cidr(cidr)", "Alias for `cidr(cidr)`.", "`ip_in_cidr(10.0.0.0/8)`."]],
    ["time_between", ["time_between(start,end)", "Checks whether request time falls in a time window.", "`time_between(09:00,18:00)`."]],
    ["range", ["range(field,min,max)", "Checks whether a numeric field is inside an inclusive range.", "`range(subject.attrs.score,1,10)`."]]
  ]),
  operators: new Map([
    ["=", ["Equality", "Compares a field to a value.", "`subject.type=user` matches when the subject type is `user`."]],
    ["==", ["Equality", "Same equality check as `=`.", "`subject.type==user`."]],
    ["!=", ["Inequality", "Matches when a field is not equal to a value.", "`subject.attrs.clearance!=high`."]],
    [">=", ["Greater-than-or-equal", "Numeric/string comparison used by the condition parser.", "`subject.attrs.level>=3`."]],
    ["@", ["Membership", "Matches when the field/list contains any listed value.", "`subject.roles@admin,superadmin`."]],
    ["in", ["Membership", "Matches against values in brackets.", "`subject.type in [user service]`."]],
    ["IN", ["Membership", "Matches against values in brackets.", "`subject.type IN [user service]`."]],
    ["contains", ["Membership", "Checks whether a list-like field contains values.", "`subject.roles contains any [admin superadmin]`."]],
    ["has_any", ["Membership", "Alias-style membership check against bracketed values.", "`subject.groups has_any [engineering ops]`."]],
    ["has", ["Membership", "Membership check against bracketed values.", "`subject.groups has [engineering]`."]],
    ["&&", ["Logical AND", "Both sides must match.", "`subject.type=user && resource.owner_id=subject.id`."]],
    ["AND", ["Logical AND", "Word form of `&&`.", "`subject.type=user AND resource.type=document`."]],
    ["||", ["Logical OR", "Either side may match.", "`subject.roles@admin || resource.owner_id=subject.id`."]],
    ["OR", ["Logical OR", "Word form of `||`.", "`subject.roles@admin OR subject.groups@ops`."]]
  ])
};

function activate(context) {
  const output = vscode.window.createOutputChannel("AuthZ DSL");
  output.appendLine("AuthZ DSL extension activated.");
  context.subscriptions.push(output);

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.text = "$(shield) AuthZ DSL";
  status.tooltip = "AuthZ DSL language features are active";
  status.command = "authz.showStatus";
  context.subscriptions.push(status);

  const diagnostics = vscode.languages.createDiagnosticCollection("authz");
  context.subscriptions.push(diagnostics);
  const lspDiagnostics = vscode.languages.createDiagnosticCollection("authz-lsp");
  context.subscriptions.push(lspDiagnostics);
  authzLspClient = startAuthzLanguageServer(context, output, lspDiagnostics);

  context.subscriptions.push(vscode.languages.registerCompletionItemProvider(language, {
    async provideCompletionItems(document, position) {
      const lspItems = await lspCompletion(document, position);
      if (lspItems) return lspItems;
      return provideCompletions(document, position);
    }
  }, " ", ":", "=", ",", ".", "@", "[", "{"));

  context.subscriptions.push(vscode.languages.registerHoverProvider(language, {
    async provideHover(document, position) {
      const lspHover = await lspHoverAt(document, position);
      if (lspHover) return lspHover;
      return provideHover(document, position);
    }
  }));

  context.subscriptions.push(vscode.languages.registerDefinitionProvider(language, {
    async provideDefinition(document, position) {
      const lspDefinition = await lspDefinitionAt(document, position);
      if (lspDefinition) return lspDefinition;
      return provideDefinition(document, position);
    }
  }));

  context.subscriptions.push(vscode.languages.registerReferenceProvider(language, {
    async provideReferences(document, position) {
      const lspReferences = await lspReferencesAt(document, position);
      if (lspReferences) return lspReferences;
      return provideReferences(document, position);
    }
  }));

  context.subscriptions.push(vscode.languages.registerRenameProvider(language, {
    async prepareRename(document, position) {
      return prepareRename(document, position);
    },
    async provideRenameEdits(document, position, newName) {
      return provideRenameEdits(document, position, newName);
    }
  }));

  context.subscriptions.push(vscode.languages.registerDocumentLinkProvider(language, {
    provideDocumentLinks(document) {
      return provideDocumentLinks(document);
    }
  }));

  context.subscriptions.push(vscode.languages.registerCodeActionsProvider(language, {
    provideCodeActions(document, range, context) {
      return provideCodeActions(document, range, context);
    }
  }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));

  context.subscriptions.push(vscode.languages.registerDocumentSymbolProvider(language, {
    async provideDocumentSymbols(document) {
      const lspSymbols = await lspDocumentSymbols(document);
      if (lspSymbols) return lspSymbols;
      return provideDocumentSymbols(document);
    }
  }));

  context.subscriptions.push(vscode.languages.registerDocumentFormattingEditProvider(language, {
    async provideDocumentFormattingEdits(document) {
      const lspEdits = await lspFormattingEdits(document);
      if (lspEdits) return lspEdits;
      return formatDocument(document);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.showReference", () => {
    const panel = vscode.window.createWebviewPanel("authzReference", "AuthZ DSL Syntax Reference", vscode.ViewColumn.Beside, {});
    panel.webview.html = renderReferenceHtml();
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.showStatus", () => {
    const editor = vscode.window.activeTextEditor;
    const languageId = editor ? editor.document.languageId : "none";
    const lspState = authzLspClient && authzLspClient.running ? "running" : "stopped";
    vscode.window.showInformationMessage(`AuthZ DSL extension is active. Current language mode: ${languageId}. LSP: ${lspState}.`);
    output.show(true);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.validateFile", async () => {
    await validateActiveFileWithCLI(output, diagnostics);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.formatFile", async () => {
    await formatActiveFileWithCLI(output);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.previewPlan", async () => {
    await previewPlan(output);
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.showPermissionGraph", async () => {
    await showPermissionGraph();
  }));

  context.subscriptions.push(vscode.commands.registerCommand("authz.explainSymbol", async () => {
    await explainActiveSymbol();
  }));

  const updateStatus = () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document.languageId === "authz") {
      status.show();
    } else {
      status.hide();
    }
  };

  const refresh = (document) => {
    if (document.languageId === "authz") {
      if (authzLspClient) authzLspClient.didOpenOrChange(document);
      diagnostics.set(document.uri, validateDocument(document));
      output.appendLine(`Validated ${document.uri.fsPath}`);
    }
  };
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(refresh));
  context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => refresh(event.document)));
  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((document) => {
    if (document.languageId === "authz") validateFileWithCLI(document, output, diagnostics);
  }));
  context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((document) => {
    diagnostics.delete(document.uri);
    lspDiagnostics.delete(document.uri);
    if (authzLspClient && document.languageId === "authz") authzLspClient.didClose(document);
  }));
  context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(updateStatus));
  vscode.workspace.textDocuments.forEach(refresh);
  updateStatus();
}

function deactivate() {
  if (authzLspClient) authzLspClient.stop();
}

function startAuthzLanguageServer(context, output, diagnostics) {
  const serverPath = path.join(context.extensionPath, "src", "server.js");
  if (!fs.existsSync(serverPath)) {
    output.appendLine(`AuthZ LSP server not found: ${serverPath}`);
    return undefined;
  }
  const client = new AuthzLSPClient(serverPath, output, diagnostics);
  context.subscriptions.push({ dispose: () => client.stop() });
  client.start();
  return client;
}

class AuthzLSPClient {
  constructor(serverPath, output, diagnostics) {
    this.serverPath = serverPath;
    this.output = output;
    this.diagnostics = diagnostics;
    this.child = undefined;
    this.buffer = Buffer.alloc(0);
    this.nextID = 1;
    this.pending = new Map();
    this.running = false;
  }

  start() {
    if (this.running) return;
    this.child = cp.spawn(process.execPath, [this.serverPath], {
      cwd: path.dirname(path.dirname(this.serverPath)),
      env: { ...process.env },
      stdio: ["pipe", "pipe", "pipe"]
    });
    this.running = true;
    this.child.stdout.on("data", (chunk) => this.read(chunk));
    this.child.stderr.on("data", (chunk) => this.output.appendLine(`[authz-lsp] ${chunk.toString().trimEnd()}`));
    this.child.on("exit", (code, signal) => {
      this.running = false;
      this.output.appendLine(`[authz-lsp] exited code=${code} signal=${signal || ""}`);
      for (const pending of this.pending.values()) pending.resolve(undefined);
      this.pending.clear();
    });
    this.initialize().catch((err) => this.output.appendLine(`[authz-lsp] initialize failed: ${err.message}`));
  }

  async initialize() {
    const folders = (vscode.workspace.workspaceFolders || []).map((folder) => ({ uri: folder.uri.toString(), name: folder.name }));
    await this.request("initialize", {
      processId: process.pid,
      rootUri: folders[0] ? folders[0].uri : null,
      workspaceFolders: folders,
      capabilities: {}
    });
    this.notify("initialized", {});
    for (const document of vscode.workspace.textDocuments) {
      if (document.languageId === "authz") this.didOpenOrChange(document, true);
    }
    this.output.appendLine("[authz-lsp] server running.");
  }

  didOpenOrChange(document, forceOpen = false) {
    if (!this.running) return;
    const uri = document.uri.toString();
    if (forceOpen) {
      this.notify("textDocument/didOpen", {
        textDocument: { uri, languageId: "authz", version: document.version, text: document.getText() }
      });
      return;
    }
    this.notify("textDocument/didChange", {
      textDocument: { uri, version: document.version },
      contentChanges: [{ text: document.getText() }]
    });
  }

  didClose(document) {
    if (!this.running) return;
    this.notify("textDocument/didClose", { textDocument: { uri: document.uri.toString() } });
  }

  request(method, params, timeoutMS = 800) {
    if (!this.running || !this.child || !this.child.stdin.writable) return Promise.resolve(undefined);
    const id = this.nextID++;
    const message = { jsonrpc: "2.0", id, method, params };
    this.write(message);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(undefined);
      }, timeoutMS);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        }
      });
    });
  }

  notify(method, params) {
    if (!this.running || !this.child || !this.child.stdin.writable) return;
    this.write({ jsonrpc: "2.0", method, params });
  }

  write(message) {
    const json = JSON.stringify(message);
    this.child.stdin.write(`Content-Length: ${Buffer.byteLength(json, "utf8")}\r\n\r\n${json}`);
  }

  read(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const sep = this.buffer.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const header = this.buffer.slice(0, sep).toString("utf8");
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (!match) {
        this.buffer = this.buffer.slice(sep + 4);
        continue;
      }
      const length = Number(match[1]);
      const start = sep + 4;
      const end = start + length;
      if (this.buffer.length < end) return;
      const raw = this.buffer.slice(start, end).toString("utf8");
      this.buffer = this.buffer.slice(end);
      try {
        this.handle(JSON.parse(raw));
      } catch (err) {
        this.output.appendLine(`[authz-lsp] bad message: ${err.message}`);
      }
    }
  }

  handle(message) {
    if (message.id !== undefined && this.pending.has(message.id)) {
      const pending = this.pending.get(message.id);
      this.pending.delete(message.id);
      pending.resolve(message.result);
      return;
    }
    if (message.method === "textDocument/publishDiagnostics" && message.params) {
      const uri = vscode.Uri.parse(message.params.uri);
      const diagnostics = (message.params.diagnostics || []).map(lspDiagnosticToVscode);
      this.diagnostics.set(uri, diagnostics);
      return;
    }
    if (message.method === "window/logMessage" && message.params) {
      this.output.appendLine(`[authz-lsp] ${message.params.message}`);
    }
  }

  stop() {
    if (!this.child) return;
    if (this.running) {
      this.request("shutdown", null, 250).finally(() => {
        try {
          this.notify("exit", null);
          this.child.kill();
        } catch {
          // Best-effort shutdown.
        }
      });
    }
    this.running = false;
  }
}

async function lspCompletion(document, position) {
  const result = await lspRequest("textDocument/completion", lspTextPosition(document, position));
  if (!result) return undefined;
  const items = Array.isArray(result) ? result : result.items;
  if (!items || items.length === 0) return undefined;
  return items.map(lspCompletionToVscode);
}

async function lspHoverAt(document, position) {
  const result = await lspRequest("textDocument/hover", lspTextPosition(document, position));
  if (!result || !result.contents) return undefined;
  return new vscode.Hover(markdownFromLsp(result.contents), lspRange(result.range));
}

async function lspDefinitionAt(document, position) {
  const result = await lspRequest("textDocument/definition", lspTextPosition(document, position));
  return lspLocations(result);
}

async function lspReferencesAt(document, position) {
  const result = await lspRequest("textDocument/references", {
    ...lspTextPosition(document, position),
    context: { includeDeclaration: true }
  });
  return lspLocations(result);
}

async function lspDocumentSymbols(document) {
  const result = await lspRequest("textDocument/documentSymbol", { textDocument: lspTextDocument(document) });
  if (!Array.isArray(result) || result.length === 0) return undefined;
  return result.map((symbol) => new vscode.DocumentSymbol(
    symbol.name,
    symbol.detail || "",
    symbolKindFromLsp(symbol.kind),
    lspRange(symbol.range),
    lspRange(symbol.selectionRange || symbol.range)
  ));
}

async function lspFormattingEdits(document) {
  const result = await lspRequest("textDocument/formatting", {
    textDocument: lspTextDocument(document),
    options: { tabSize: 2, insertSpaces: true }
  });
  if (!Array.isArray(result) || result.length === 0) return undefined;
  return result.map((edit) => vscode.TextEdit.replace(lspRange(edit.range), edit.newText));
}

function lspRequest(method, params) {
  if (!authzLspClient || !authzLspClient.running) return Promise.resolve(undefined);
  return authzLspClient.request(method, params);
}

function lspTextPosition(document, position) {
  return { textDocument: lspTextDocument(document), position: { line: position.line, character: position.character } };
}

function lspTextDocument(document) {
  return { uri: document.uri.toString() };
}

function lspCompletionToVscode(item) {
  const completionItem = new vscode.CompletionItem(item.label, completionKindFromLsp(item.kind));
  completionItem.detail = item.detail;
  completionItem.documentation = item.documentation ? markdownFromLsp(item.documentation) : undefined;
  if (item.insertText) {
    completionItem.insertText = item.insertTextFormat === 2 ? new vscode.SnippetString(item.insertText) : item.insertText;
  }
  return completionItem;
}

function markdownFromLsp(value) {
  if (!value) return undefined;
  if (typeof value === "string") return new vscode.MarkdownString(value);
  if (Array.isArray(value)) return new vscode.MarkdownString(value.map((item) => typeof item === "string" ? item : item.value || "").join("\n\n"));
  return new vscode.MarkdownString(value.value || "");
}

function lspLocations(result) {
  if (!result) return undefined;
  const values = Array.isArray(result) ? result : [result];
  if (values.length === 0) return undefined;
  return values.map((loc) => new vscode.Location(vscode.Uri.parse(loc.uri), lspRange(loc.range)));
}

function lspRange(range) {
  if (!range) return undefined;
  return new vscode.Range(range.start.line, range.start.character, range.end.line, range.end.character);
}

function lspDiagnosticToVscode(diagnostic) {
  const out = new vscode.Diagnostic(lspRange(diagnostic.range), diagnostic.message, diagnosticSeverityFromLsp(diagnostic.severity));
  out.source = diagnostic.source || "authz-lsp";
  return out;
}

function diagnosticSeverityFromLsp(severity) {
  if (severity === 1) return vscode.DiagnosticSeverity.Error;
  if (severity === 2) return vscode.DiagnosticSeverity.Warning;
  if (severity === 3) return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Hint;
}

function completionKindFromLsp(kind) {
  const map = {
    3: vscode.CompletionItemKind.Function,
    5: vscode.CompletionItemKind.Field,
    10: vscode.CompletionItemKind.Property,
    12: vscode.CompletionItemKind.Value,
    14: vscode.CompletionItemKind.Keyword,
    17: vscode.CompletionItemKind.File,
    18: vscode.CompletionItemKind.Reference,
    20: vscode.CompletionItemKind.EnumMember,
    24: vscode.CompletionItemKind.Operator
  };
  return map[kind] || vscode.CompletionItemKind.Text;
}

function symbolKindFromLsp(kind) {
  const map = {
    3: vscode.SymbolKind.Namespace,
    5: vscode.SymbolKind.Class,
    6: vscode.SymbolKind.Method,
    8: vscode.SymbolKind.Field,
    9: vscode.SymbolKind.Constructor,
    10: vscode.SymbolKind.Enum,
    12: vscode.SymbolKind.Function,
    13: vscode.SymbolKind.Variable,
    18: vscode.SymbolKind.Array,
    19: vscode.SymbolKind.Object,
    20: vscode.SymbolKind.Key,
    22: vscode.SymbolKind.Event
  };
  return map[kind] || vscode.SymbolKind.String;
}

async function provideCompletions(document, position) {
  const text = document.lineAt(position.line).text.slice(0, position.character);
  const parsed = parseLine(text);
  const index = await buildWorkspaceIndex(document);
  const items = [];
  const block = blockContextAt(document, position.line);

  if (block && !isBlockHeader(parsed.tokens)) {
    return blockCompletions(block.directive, parsed, text, index);
  }

  if (parsed.tokens.length === 0 || (parsed.tokens.length === 1 && !text.endsWith(" "))) {
    for (const [name, syntax, description] of directives) {
      items.push(completion(name, vscode.CompletionItemKind.Keyword, description, syntax));
    }
    return items;
  }

  const directive = parsed.tokens[0];
  const tokenIndex = parsed.tokens.length - (text.endsWith(" ") ? 0 : 1);
  const optionValue = currentOptionValue(text);

  if (optionValue) {
    return optionValueCompletions(directive, optionValue, index);
  }

  if (directive === "engine") {
    return engineOptions.map(([label, detail]) => completion(label, vscode.CompletionItemKind.Property, detail));
  }

  if (directive === "include") {
    return [completion("\"./*.authz\"", vscode.CompletionItemKind.File, "Include another AuthZ DSL file")];
  }

  if (directive === "policy") {
    if (tokenIndex === 1) return idCompletions("policy");
    if (tokenIndex === 2) return index.tenants.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Tenant ID"));
    if (tokenIndex === 3) return effects.map((id) => completion(id, vscode.CompletionItemKind.EnumMember, "Policy effect"));
    if (tokenIndex === 4) return actionCompletions(index);
    if (tokenIndex === 5) return resourceCompletions(index);
    if (tokenIndex === 6 || inConditionContext(text, parsed)) return conditionCompletions();
  }

  if (directive === "role") {
    if (tokenIndex === 1) return idCompletions("role");
    if (tokenIndex === 2) return index.tenants.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Tenant ID"));
    if (tokenIndex === 4) return permissionCompletions();
    return optionCompletions(directive, index);
  }

  if (directive === "acl") {
    if (tokenIndex === 1) return idCompletions("acl");
    if (tokenIndex === 2) return resourceCompletions(index);
    if (tokenIndex === 3) return subjectCompletions(index);
    if (tokenIndex === 4) return actionCompletions(index);
    if (tokenIndex === 5) return effects.map((id) => completion(id, vscode.CompletionItemKind.EnumMember, "ACL effect"));
  }

  if (["tenant", "user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive)) {
    if (tokenIndex === 1) return idCompletions(directive.replace("_", "-"));
    if (tokenIndex === 2 && directive !== "tenant") {
      return index.tenants.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Tenant ID"));
    }
    if (directive === "invitation" && tokenIndex === 4) return index.roles.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Role ID"));
    if (directive === "api_key" && tokenIndex === 3) return index.users.map((id) => completion(id, vscode.CompletionItemKind.Reference, "User ID"));
    if (directive === "boundary" && tokenIndex === 4) return actionCompletions(index);
    if (directive === "boundary" && tokenIndex === 5) return resourceCompletions(index);
    if (expectsStatus(directive, text)) {
      return (directive === "invitation" ? inviteStatuses : userStatuses).map((id) => completion(id, vscode.CompletionItemKind.EnumMember, "Status"));
    }
  }

  if (directive === "member") {
    if (tokenIndex === 1) return subjectCompletions(index);
    if (tokenIndex === 2) return index.roles.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Role ID"));
  }

  if (directive === "boundary") {
    if (tokenIndex === 4) return actions.map((id) => completion(id, vscode.CompletionItemKind.Value, "Action"));
    if (tokenIndex === 5) return resources.map((id) => completion(id, vscode.CompletionItemKind.Value, "Resource pattern"));
  }

  items.push(...optionCompletions(directive, index));
  return items;
}

function blockCompletions(directive, parsed, text, index) {
  const tokens = parsed.tokens;
  if (tokens.length === 0 || (tokens.length === 1 && !text.endsWith(" "))) {
    const fields = directive === "members" ? [] : (blockFieldsByDirective[directive] || []);
    return fields.map((field) => completion(field, vscode.CompletionItemKind.Property, `Block field for ${directive}`));
  }
  const field = tokens[0];
  if (field === "tenant") return index.tenants.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Tenant ID"));
  if (field === "effect") return effects.map((id) => completion(id, vscode.CompletionItemKind.EnumMember, "Effect"));
  if (field === "actions" || field === "owner_actions") return actionCompletions(index);
  if (field === "resources" || field === "resource") return resourceCompletions(index);
  if (field === "subject") return subjectCompletions(index);
  if (field === "permissions") return permissionCompletions();
  if (field === "inherits" || field === "roles") return index.roles.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Role ID"));
  if (field === "when" || inBlockConditionContext(block, field)) return conditionCompletions();
  if (directive === "members" && tokens.length <= 2) return index.roles.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Role ID"));
  return [];
}

function optionCompletions(directive, index) {
  const base = (optionsByDirective[directive] || []).map(([label, detail]) => completion(label, vscode.CompletionItemKind.Property, detail));
  if (directive === "role") {
    base.push(...index.roles.map((id) => completion(`inherits:${id}`, vscode.CompletionItemKind.Reference, "Inherit role")));
  }
  if (["service_account", "invitation"].includes(directive)) {
    base.push(...index.roles.map((id) => completion(`roles:${id}`, vscode.CompletionItemKind.Reference, "Role list")));
  }
  if (directive === "invitation") {
    base.push(...index.groups.map((id) => completion(`groups:${id}`, vscode.CompletionItemKind.Reference, "Group list")));
    base.push(...index.users.map((id) => completion(`invited_by:${id}`, vscode.CompletionItemKind.Reference, "Inviting user")));
  }
  if (["service_account", "api_key"].includes(directive)) {
    base.push(...index.scopes.map((id) => completion(`scopes:${id}`, vscode.CompletionItemKind.Reference, "Scope list")));
  }
  return base;
}

function optionValueCompletions(directive, optionValue, index) {
  const key = optionValue.key;
  if (key === "status:") {
    return (directive === "invitation" ? inviteStatuses : userStatuses).map((id) => completion(id, vscode.CompletionItemKind.EnumMember, "Status"));
  }
  if (key === "parent:" && directive === "tenant") return index.tenants.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Parent tenant"));
  if (key === "parent:" && directive === "group") return index.groups.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Parent group"));
  if (key === "parent:" && directive === "scope") return index.scopes.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Parent scope"));
  if (key === "inherits:" || key === "roles:") return index.roles.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Role ID"));
  if (key === "scopes:") return index.scopes.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Scope ID"));
  if (key === "groups:") return index.groups.map((id) => completion(id, vscode.CompletionItemKind.Reference, "Group ID"));
  if (key === "invited_by:") return index.users.map((id) => completion(id, vscode.CompletionItemKind.Reference, "User ID"));
  if (key === "owner:") return actionCompletions(index);
  if (key === "expires:") return [completion(new Date(Date.now() + 86400000).toISOString(), vscode.CompletionItemKind.Value, "RFC3339 timestamp")];
  return optionCompletions(directive, index);
}

function conditionCompletions() {
  return [
    ...conditionFields.map((id) => completion(id, vscode.CompletionItemKind.Field, "Condition field")),
    ...conditionOperators.map((id) => completion(id, vscode.CompletionItemKind.Operator, "Condition operator")),
    ...conditionFunctions.map(([insertText, detail]) => completion(insertText.replace(/\$\{\d+:([^}]+)\}/g, "$1"), vscode.CompletionItemKind.Function, detail, insertText))
  ];
}

function actionCompletions(index) {
  return unique([...actions, ...index.actions]).map((id) => completion(id, vscode.CompletionItemKind.Value, "Action"));
}

function resourceCompletions(index) {
  return unique([...resources, ...index.resources]).map((id) => completion(id, vscode.CompletionItemKind.Value, "Resource pattern"));
}

function subjectCompletions(index) {
  return unique([...subjects, ...index.subjects]).map((id) => completion(id, vscode.CompletionItemKind.Reference, "Subject"));
}

function permissionCompletions() {
  return [
    completion("*:*", vscode.CompletionItemKind.Value, "All actions on all resources"),
    ...actions.filter((a) => a !== "*").map((a) => completion(`${a}:document:*`, vscode.CompletionItemKind.Value, `${a} on documents`)),
    completion("GET:route:GET:/admin/*", vscode.CompletionItemKind.Value, "GET route permission"),
    completion("POST:route:POST:/admin/*", vscode.CompletionItemKind.Value, "POST route permission")
  ];
}

function idCompletions(prefix) {
  return [completion(`${prefix}-${Date.now().toString(36).slice(-4)}`, vscode.CompletionItemKind.Value, "Suggested ID")];
}

function completion(label, kind, detail, snippet) {
  const item = new vscode.CompletionItem(label, kind);
  item.detail = detail;
  if (snippet) {
    item.insertText = new vscode.SnippetString(snippet);
  }
  return item;
}

async function provideHover(document, position) {
  const line = document.lineAt(position.line).text;
  const parsed = parseLine(line);
  const tokenInfo = tokenAt(parsed, position.character);
  const wordRange = document.getWordRangeAtPosition(position, /[A-Za-z_][\w.-]*/);
  const word = tokenInfo ? tokenInfo.value : (wordRange ? document.getText(wordRange) : "");
  if (!word) return undefined;

  const tokenIndex = tokenInfo ? parsed.tokenInfos.indexOf(tokenInfo) : -1;
  const directive = parsed.tokens[0];
  const index = await buildWorkspaceIndex(document);
  const block = blockContextAt(document, position.line);
  if (block && !isBlockHeader(parsed.tokens)) {
    const blockHover = hoverForBlockToken(document, block, parsed, tokenIndex, tokenInfo, position, index);
    if (blockHover) return blockHover;
  }
  const contextualHover = hoverForContext(directive, tokenIndex, tokenInfo, position, index);
  if (contextualHover) return contextualHover;

  if (directiveDocs.has(word)) {
    const doc = directiveDocs.get(word);
    return explanationHover(word, doc.description, "This directive creates or configures part of the authorization model.", `Syntax: \`${doc.syntax}\``);
  }
  if (explanationRegistry.functions.has(word)) {
    const [title, summary, example] = explanationRegistry.functions.get(word);
    return explanationHover(title, summary, "Used inside policy conditions during ABAC evaluation.", example);
  }
  const fieldHover = hoverForConditionField(word);
  if (fieldHover) return fieldHover;
  const operatorHover = hoverForOperator(word);
  if (operatorHover) return operatorHover;

  if (word === "*") {
    return explanationHover("Wildcard `*`", "Matches any action or any resource depending on where it appears.", "Broad wildcards can grant large access surfaces; deny rules still take precedence.", "`policy p org allow * * true` allows any action on any resource when the condition is true.");
  }

  const symbolHover = hoverForSymbol(document, directive, tokenIndex, tokenInfo, position, index);
  if (symbolHover) return symbolHover;

  const optionHover = hoverForOption(word, directive);
  if (optionHover) return optionHover;

  if (effects.includes(word)) return hoverForEffect(word);
  if (actions.includes(word)) return hoverForAction(word);
  if (isPermissionLike(word)) return hoverForPermission(word, index);
  if (isSubjectLike(word)) return hoverForSubject(word, index);
  if (isResourceLike(word)) return hoverForResourcePattern(word, index);
  return undefined;
}

async function provideDefinition(document, position) {
  const line = document.lineAt(position.line).text;
  const parsed = parseLine(line);
  const tokenInfo = tokenAt(parsed, position.character);
  if (!tokenInfo || parsed.tokens.length === 0) return undefined;

  const directive = parsed.tokens[0];
  const tokenIndex = parsed.tokenInfos.indexOf(tokenInfo);
  const index = await buildWorkspaceIndex(document);
  const block = blockContextAt(document, position.line);
  const blockField = block ? blockFieldAt(document, block, position.line) : "";
  const blockValueToken = block ? isBlockValueLine(blockField, parsed.tokens) : false;
  const keys = block && !isBlockHeader(parsed.tokens)
    ? definitionKeysForBlockToken(block.directive, blockField || parsed.tokens[0], tokenIndex, tokenInfo, position.character, blockValueToken)
    : definitionKeysForToken(directive, tokenIndex, tokenInfo, position.character);
  const locations = [];
  for (const key of keys) {
    const found = index.definitions.get(key);
    if (found) locations.push(...found);
  }
  return locations.length > 0 ? locations : undefined;
}

function hoverForSymbol(document, directive, tokenIndex, tokenInfo, position, index) {
  if (!tokenInfo) return undefined;
  const keys = definitionKeysForToken(directive, tokenIndex, tokenInfo, position.character);
  const key = keys.find((candidate) => index.definitions.has(candidate));
  if (key) {
    const entry = entryForKey(index, key);
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${entry ? entry.directive : "reference"}** \`${tokenInfo.value}\`\n\n`);
    md.appendMarkdown(entry ? `Defined on line ${entry.selectionRange.start.line + 1}.` : "Definition available in this file.");
    md.appendMarkdown("\n\nUse **Go to Definition** (`F12`) or **Cmd/Ctrl+Click**.");
    return new vscode.Hover(md);
  }

  if (tokenIndex === 1 && isDefinitionDirective(directive)) {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${directive}** \`${tokenInfo.value}\`\n\nDefines a ${directive.replace("_", " ")} entry.`);
    return new vscode.Hover(md);
  }
  return undefined;
}

function hoverForBlockToken(document, block, parsed, tokenIndex, tokenInfo, position, index) {
  if (!tokenInfo || tokenIndex < 0) return undefined;
  const field = blockFieldAt(document, block, position.line) || parsed.tokens[0];
  const valueToken = isBlockValueLine(field, parsed.tokens);
  const token = tokenInfo.value;
  if (tokenIndex === 0 && !valueToken) {
    if ((blockFieldsByDirective[block.directive] || []).includes(field)) {
      return explanationHover(`${block.directive} field \`${field}\``, "Block-form field.", "This field is normalized into the same config model as the compact inline DSL.", "");
    }
    if (block.directive === "members") return hoverForSubject(token, index);
  }

  const keys = definitionKeysForBlockToken(block.directive, field, tokenIndex, tokenInfo, position.character, valueToken);
  const key = keys.find((candidate) => index.definitions.has(candidate));
  if (key) {
    const entry = entryForKey(index, key);
    if (entry) return hoverForEntryBehavior(entry, index);
    return explanationHover("Reference", `Reference to \`${token}\`.`, "Definition available in the indexed AuthZ config.", "Use Go to Definition (`F12`) or Cmd/Ctrl+Click.");
  }

  if (field === "effect") return hoverForEffect(token);
  if (field === "actions" || field === "owner_actions") return hoverForAction(token);
  if (field === "resources" || field === "resource") return hoverForResourcePattern(token, index);
  if (field === "permissions") return hoverForPermission(token, index);
  if (field === "subject") return hoverForSubject(token, index);
  if (field === "when" || isConditionLike(token)) return hoverForCondition(token) || hoverForConditionField(token) || hoverForOperator(token);
  if (block.directive === "members" && tokenIndex > 0) return hoverForRoleReference(cleanBlockValue(token), index);
  return undefined;
}

function hoverForOption(token, directive) {
  const option = token.includes(":") ? `${token.slice(0, token.indexOf(":"))}:` : token;
  if (explanationRegistry.options.has(option)) {
    const doc = explanationRegistry.options.get(option);
    const value = token.includes(":") ? token.slice(token.indexOf(":") + 1) : "";
    return explanationHover(doc.title, doc.summary, doc.runtime, value ? `${doc.example}\n\nCurrent value: \`${value}\`.` : doc.example);
  }
  const engine = engineOptions.find(([label]) => token.startsWith(label));
  if (engine) {
    const doc = explanationRegistry.engine.get(engine[0]);
    if (doc) return explanationHover(doc[0], doc[1], "This changes engine/runtime behavior, not policy matching syntax.", doc[2]);
    return explanationHover(engine[0], engine[1], "Engine setting.", "");
  }
  return undefined;
}

function hoverForOptionBehavior(token, directive, index) {
  const idx = token.indexOf(":");
  if (idx <= 0) return undefined;
  const key = token.slice(0, idx);
  const values = splitList(token.slice(idx + 1));
  if ((key === "inherits" || key === "roles") && values.length) {
    const lines = values.flatMap((roleID) => {
      const role = findEntry(index, "role", roleID);
      if (!role) return [`\`${roleID}\` is referenced, but no role definition was found in the indexed config.`];
      return [`\`${roleID}\` contributes effective permissions ${formatInlineList(resolveRolePermissions(roleID, index))}.`];
    });
    return behaviorHover(`${token} intrinsic behavior`, [
      key === "inherits" ? "This entry receives permissions from the referenced parent role(s)." : "This entry is associated with the referenced role(s).",
      ...lines
    ]);
  }
  if (key === "parent" && values[0]) {
    const parent = findEntry(index, directive === "tenant" ? "tenant" : directive, values[0]);
    return behaviorHover(`${token} intrinsic behavior`, [
      `Creates a parent relationship to \`${values[0]}\`.`,
      parent ? `The parent entry is defined in the indexed config.` : "No matching parent definition was found in the indexed config.",
      directive === "tenant" ? "Tenant hierarchy can affect ancestor/cross-tenant checks through the tenant resolver." : "This hierarchy is stored as IAM metadata."
    ]);
  }
  return undefined;
}

function hoverForContext(directive, tokenIndex, tokenInfo, position, index) {
  if (!tokenInfo || !directive) return undefined;
  const token = tokenInfo.value;
  const definingEntry = tokenIndex === 1 ? findEntry(index, directive, token) : undefined;
  if (definingEntry) return hoverForEntryBehavior(definingEntry, index);

  if (directive === "engine") {
    const engine = engineOptions.find(([label]) => token.startsWith(label));
    if (engine) return hoverForOption(token, directive);
  }

  if (token.includes(":")) {
    const option = hoverForOption(token, directive);
    if (option && !isResourcePosition(directive, tokenIndex) && !isSubjectPosition(directive, tokenIndex) && !isPermissionPosition(directive, tokenIndex)) {
      return hoverForOptionBehavior(token, directive, index) || option;
    }
  }

  if (directive === "policy") {
    if (tokenIndex === 1) return explanationHover("Policy ID", "Unique name for this ABAC policy.", "Used in diagnostics, apply plans, audit/explain traces, and editor references.", `This policy is named \`${token}\`.`);
    if (tokenIndex === 2) return explanationHover("Policy tenant", "Tenant where this policy is loaded.", "During authorization, policies are selected for the relevant tenant context.", `This policy belongs to tenant \`${token}\`.`);
    if (tokenIndex === 3) return hoverForEffect(token);
    if (tokenIndex === 4) return hoverForActionList(token);
    if (tokenIndex === 5) return hoverForResourceList(token, index);
    if (tokenIndex === 6) return hoverForCondition(token);
  }

  if (directive === "role") {
    if (tokenIndex === 1) return explanationHover("Role ID", "Unique role identifier used by RBAC membership and inheritance.", "Subjects assigned this role can receive its permissions.", `Role ID: \`${token}\`.`);
    if (tokenIndex === 2) return explanationHover("Role tenant", "Tenant where this role exists.", "Role checks are evaluated in tenant context.", `Tenant: \`${token}\`.`);
    if (tokenIndex === 3) return explanationHover("Role name", "Human-readable role name.", "Metadata only; the role ID is what memberships reference.", `Display name: \`${token}\`.`);
    if (tokenIndex === 4) return hoverForPermissionList(token, index);
  }

  if (directive === "acl") {
    if (tokenIndex === 1) return explanationHover("ACL ID", "Unique identifier for this explicit ACL entry.", "Used for diagnostics, apply plans, and traces.", `ACL ID: \`${token}\`.`);
    if (tokenIndex === 2) return hoverForResourcePattern(token, index);
    if (tokenIndex === 3) return hoverForSubject(token, index);
    if (tokenIndex === 4) return hoverForActionList(token);
    if (tokenIndex === 5) return hoverForEffect(token);
  }

  if (directive === "member") {
    if (tokenIndex === 1) return hoverForSubject(token, index);
    if (tokenIndex === 2) return hoverForRoleReference(token, index);
  }

  if (directive === "tenant") {
    if (tokenIndex === 1) return explanationHover("Tenant ID", "Unique tenant identifier.", "Policies, roles, IAM objects, and environment checks refer to tenants by ID.", `Tenant ID: \`${token}\`.`);
    if (tokenIndex === 2) return explanationHover("Tenant name", "Human-readable tenant name.", "Metadata only; authorization references use the tenant ID.", `Display name: \`${token}\`.`);
  }

  if (["user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive)) {
    if (tokenIndex === 1) return explanationHover(`${directive.replace("_", " ")} ID`, "Unique identifier for this IAM/config entry.", "Other DSL entries can reference this ID where applicable.", `ID: \`${token}\`.`);
    if (tokenIndex === 2) return explanationHover("Tenant reference", "Tenant that owns this IAM/config entry.", "Used when applying IAM objects and keeping configuration tenant-scoped.", `Tenant: \`${token}\`.`);
  }

  if (directive === "boundary") {
    if (tokenIndex === 4) return hoverForActionList(token);
    if (tokenIndex === 5) return hoverForResourceList(token, index);
  }

  if (isConditionLike(token)) return hoverForCondition(token);
  if (isPermissionPosition(directive, tokenIndex) || isPermissionLike(token)) return hoverForPermissionList(token, index);
  if (isSubjectPosition(directive, tokenIndex) || isSubjectLike(token)) return hoverForSubject(token, index);
  if (isResourcePosition(directive, tokenIndex) || isResourceLike(token)) return hoverForResourcePattern(token, index);
  if (actions.includes(token)) return hoverForAction(token);
  if (effects.includes(token)) return hoverForEffect(token);
  return undefined;
}

function hoverForEffect(effect) {
  if (effect === "deny") {
    return explanationHover("Effect `deny`", "Blocks matching authorization requests.", "Deny policies and deny ACLs are checked before allow grants, so a matching deny wins over matching allows.", "`policy deny-sensitive org1 deny read document:sensitive:* subject.type=user`.");
  }
  return explanationHover("Effect `allow`", "Grants access when the action, resource, and condition/subject match.", "Allows can come from policies, ACLs, RBAC roles, owner rules, or cross-tenant admin status; matching denies still override allows.", "`policy allow-read org1 allow read document:* subject.type=user`.");
}

function hoverForAction(action) {
  return explanationHover(`Action \`${action}\``, "The operation being authorized.", "Actions are exact strings such as `read` or HTTP methods such as `GET`; `*` means any action.", "`read`, `write`, `delete`, `GET`, and custom action names are all valid.");
}

function hoverForActionList(value) {
  const items = value.split(",").filter(Boolean);
  return explanationHover("Action list", "Comma-separated actions this policy, ACL, or boundary applies to.", "`*` means every action. Multiple actions match if the runtime action equals any item.", `Current actions: ${items.map((x) => `\`${x}\``).join(", ")}.`);
}

function hoverForResourceList(value, index) {
  const items = value.split(",").filter(Boolean);
  const warning = items.some((item) => item === "*" || item.endsWith(":*")) ? "\n\nWarning: wildcard resources are broad. Pair them with precise conditions or lower-risk effects." : "";
  const related = index ? relatedResourceLines(items, index) : [];
  return behaviorHover("Resource pattern list", [
    "Comma-separated resource patterns.",
    "A request matches when its runtime resource `type:id` matches any listed pattern.",
    `Current resources: ${items.map((x) => `\`${x}\``).join(", ")}.${warning}`,
    ...related
  ]);
}

function hoverForResourcePattern(pattern, index) {
  const related = index ? relatedResourceLines([pattern], index) : [];
  if (pattern === "*") return behaviorHover("Resource wildcard `*`", ["Matches every resource type and ID.", "This is a broad grant/deny surface. Deny rules still override allows.", "`policy allow-admin org1 allow * * subject.roles@admin`.", ...related]);
  if (pattern === "route:*") return behaviorHover("Route wildcard `route:*`", ["Matches every HTTP route resource.", "Middleware represents route resources as `route:<METHOD>:<path>`. This pattern covers all methods and paths.", "`route:*` matches `route:GET:/users/1` and `route:POST:/admin/create`.", ...related]);
  if (pattern.startsWith("route:")) return behaviorHover("Route resource pattern", ["Matches HTTP route permissions.", "Route resources use `Type=\"route\"` and ID `<METHOD>:<path>`, so patterns look like `route:GET:/users/*`.", `\`${pattern}\` applies to matching middleware route checks.`, ...related]);
  const parts = pattern.split(":");
  if (parts.length >= 2) {
    const type = parts[0];
    const id = parts.slice(1).join(":");
    const runtime = id === "*" ? `Matches any resource whose type is \`${type}\`.` : `Matches resource type \`${type}\` with ID/pattern \`${id}\`.`;
    const warning = id === "*" ? "Wildcard IDs are broad; combine with conditions when possible." : "";
    return behaviorHover(`Resource pattern \`${pattern}\``, ["Generic resources are matched as `type:id`.", runtime, warning || `Example runtime resource: \`{ Type: "${type}", ID: "${id}" }\`.`, ...related]);
  }
  return behaviorHover(`Resource \`${pattern}\``, ["Resource pattern used by policy, ACL, or role permission.", "Most resources should use `type:id` or `type:*`.", "`document:*` matches any document.", ...related]);
}

function hoverForSubject(subject, index) {
  const related = index ? subjectBehaviorLines(subject, index) : [];
  if (subject === "*") return behaviorHover("Subject wildcard `*`", ["Matches any subject.", "Use carefully in ACLs because it can grant or deny access to everyone.", "`acl public document:* * read allow` would allow any subject to read documents.", ...related]);
  if (subject === "guest") return behaviorHover("Guest subject", ["Represents unauthenticated or anonymous access.", "Useful for public route/document ACLs.", "`acl acl-route-public route:GET:/public/info guest GET allow`.", ...related]);
  if (subject.startsWith("user:")) return behaviorHover("User subject", ["Targets a specific user subject ID.", "ACLs compare this against the runtime subject ID.", `\`${subject}\` matches only that user subject.`, ...related]);
  if (subject.startsWith("group:")) return behaviorHover("Group subject", ["Targets subjects in a group.", "ACL checks can allow a subject whose groups include this group ID.", `\`${subject}\` matches members of that group.`, ...related]);
  if (subject.startsWith("service:")) return behaviorHover("Service subject", ["Targets a service/service-account style subject.", "Useful for machine-to-machine authorization.", `\`${subject}\`.`, ...related]);
  return behaviorHover(`Subject \`${subject}\``, ["The identity being granted or denied access.", "Subjects can be users, groups, services, guests, or wildcards.", "`user:alice`, `group:engineering`, `guest`.", ...related]);
}

function hoverForPermissionList(value, index) {
  const perms = value.split(",").filter(Boolean);
  if (perms.length === 1) return hoverForPermission(perms[0], index);
  const broad = perms.some((perm) => perm === "*:*" || perm.startsWith("*:") || perm.endsWith(":*"));
  const behavior = index ? permissionBehaviorLines(perms, index) : [];
  return behaviorHover("Role permission list intrinsic behavior", [
    "Comma-separated `action:resource` permissions assigned to a role.",
    "A subject with this role can perform any listed action on matching resources unless a deny overrides it.",
    `Current permissions: ${perms.map((x) => `\`${x}\``).join(", ")}.`,
    broad ? "Warning: this list contains wildcard permissions." : "",
    ...behavior
  ]);
}

function hoverForPermission(permission, index) {
  const behavior = index ? permissionBehaviorLines([permission], index) : [];
  if (permission === "*:*") {
    return behaviorHover("Permission `*:*` intrinsic behavior", [
      "Allows any action on any resource for this role.",
      "Implicitly includes `read`, `write`, `delete`, HTTP methods, custom actions, every existing resource type, and future resource patterns.",
      "This is the broadest RBAC permission. Explicit deny policies and deny ACLs still override it.",
      "`role admin org1 Administrator *:*`.",
      ...behavior
    ]);
  }
  const idx = permission.indexOf(":");
  if (idx <= 0) return undefined;
  const action = permission.slice(0, idx);
  const resource = permission.slice(idx + 1);
  const actionText = action === "*" ? "any action" : `action \`${action}\``;
  const resourceText = resource === "*" ? "any resource" : `resource pattern \`${resource}\``;
  return behaviorHover(`Permission \`${permission}\` intrinsic behavior`, [
    "RBAC permissions use `action:resource`.",
    `A subject with this role may perform ${actionText} on ${resourceText}, unless a deny rule wins.`,
    resource.endsWith(":*") ? `Implicitly covers every ID under \`${resource.slice(0, -2)}\`; for example \`${resource.slice(0, -1)}123\` would match.` : "",
    action === "*" ? "The action wildcard means this permission covers every operation on the matched resource pattern." : "",
    resource === "*" ? "The resource wildcard means this permission covers every resource type and ID." : "",
    action === "*" || resource === "*" || resource.endsWith(":*") ? "Warning: wildcard permissions are powerful; prefer narrower actions/resources when possible." : "",
    ...behavior
  ]);
}

function hoverForCondition(condition) {
  const op = conditionOperator(condition);
  if (!op) return explanationHover("Policy condition", "ABAC predicate that must evaluate true for the policy to match.", "The engine evaluates it against runtime subject, resource, action, and environment values.", `Condition: \`${condition}\`.`);
  const parts = splitCondition(condition, op);
  if (!parts) return undefined;
  const [left, right] = parts;
  if (op === "@") {
    return explanationHover("Membership condition", "Checks whether a field/list contains any listed value.", `The engine reads \`${left}\` from runtime context and matches it against ${right.split(",").map((x) => `\`${x}\``).join(", ")}.`, `\`${condition}\` is true if any listed value is present.`);
  }
  if (op === "=" || op === "==") {
    return explanationHover("Equality condition", "Checks whether a runtime field equals a value.", `The engine reads \`${left}\` and compares it with \`${right}\`.`, `\`${condition}\`.`);
  }
  if (op === "!=") {
    return explanationHover("Inequality condition", "Checks whether a runtime field is not equal to a value.", `The engine reads \`${left}\` and succeeds when it differs from \`${right}\`.`, `\`${condition}\`.`);
  }
  if (op === ">=") {
    return explanationHover("Comparison condition", "Checks whether a runtime field is greater than or equal to a value.", `The engine compares \`${left}\` with \`${right}\`.`, `\`${condition}\`.`);
  }
  return hoverForOperator(op);
}

function hoverForConditionField(field) {
  let doc = explanationRegistry.fields.get(field);
  if (!doc && field.startsWith("subject.attrs.")) doc = explanationRegistry.fields.get("subject.attrs.");
  if (!doc && field.startsWith("resource.attrs.")) doc = explanationRegistry.fields.get("resource.attrs.");
  if (!doc && field.startsWith("env.extra.")) doc = explanationRegistry.fields.get("env.extra.");
  if (!doc) return undefined;
  return explanationHover(doc[0], doc[1], "Field values come from the runtime authorization request.", doc[2]);
}

function hoverForOperator(op) {
  const doc = explanationRegistry.operators.get(op.trim());
  if (!doc) return undefined;
  return explanationHover(doc[0], doc[1], "Used inside policy conditions.", doc[2]);
}

function isConditionLike(value) {
  return /^(subject|resource|env)\./.test(value) || /^action(?:[=!>@]| IN )/.test(value) || /\b(AND|OR|IN)\b|&&|\|\|/.test(value) || /^[A-Za-z_][\w_]*\(.+\)$/.test(value);
}

function conditionOperator(condition) {
  for (const op of ["!=", ">=", "==", "=", "@"]) {
    if (condition.includes(op)) return op;
  }
  return "";
}

function splitCondition(condition, op) {
  const idx = condition.indexOf(op);
  if (idx < 0) return undefined;
  return [condition.slice(0, idx).trim(), condition.slice(idx + op.length).trim()];
}

function isResourcePosition(directive, tokenIndex) {
  return (directive === "policy" && tokenIndex === 5) || (directive === "acl" && tokenIndex === 2) || (directive === "boundary" && tokenIndex === 5);
}

function isSubjectPosition(directive, tokenIndex) {
  return (directive === "acl" && tokenIndex === 3) || (directive === "member" && tokenIndex === 1);
}

function isPermissionPosition(directive, tokenIndex) {
  return directive === "role" && tokenIndex === 4;
}

function explanationHover(title, summary, runtime, example) {
  const md = new vscode.MarkdownString();
  md.supportHtml = false;
  md.isTrusted = false;
  md.appendMarkdown(`**${title}**\n\n${summary}`);
  if (runtime) md.appendMarkdown(`\n\n${runtime}`);
  if (example) md.appendMarkdown(`\n\n${example}`);
  return new vscode.Hover(md);
}

function behaviorHover(title, bullets) {
  const md = new vscode.MarkdownString();
  md.supportHtml = false;
  md.isTrusted = false;
  md.appendMarkdown(`**${title}**\n\n`);
  for (const bullet of bullets.filter(Boolean)) {
    md.appendMarkdown(`- ${bullet}\n`);
  }
  return new vscode.Hover(md);
}

function hoverForEntryBehavior(entry, index) {
  if (!entry) return undefined;
  if (entry.directive === "policy") return hoverForPolicyEntry(entry, index);
  if (entry.directive === "role") return hoverForRoleEntry(entry, index);
  if (entry.directive === "acl") return hoverForACLEntry(entry);
  if (entry.directive === "tenant") return hoverForTenantEntry(entry, index);
  if (entry.directive === "boundary") return hoverForBoundaryEntry(entry);
  return behaviorHover(`${entry.directive} \`${entry.id}\``, [
    "Defines an IAM/config object that can be applied through the AuthZ config workflow.",
    entry.details.tenant ? `Belongs to tenant \`${entry.details.tenant}\`.` : "",
    "Other directives may reference this entry depending on its type."
  ]);
}

function hoverForPolicyEntry(entry, index) {
  const d = entry.details;
  const actionText = d.actions.map((x) => `\`${x}\``).join(", ");
  const resourceText = d.resources.map((x) => `\`${x}\``).join(", ");
  const effectText = d.effect === "deny" ? "blocks" : "allows";
  const roles = rolesMentionedInCondition(d.condition);
  const subjects = index && roles.length ? subjectsWithRoles(roles, index) : [];
  return behaviorHover(`Policy \`${entry.id}\` intrinsic behavior`, [
    `When a request is evaluated in tenant \`${d.tenant}\`, this policy ${effectText} actions ${actionText || "`<none>`"} on resources ${resourceText || "`<none>`"}.`,
    `It only matches when condition \`${d.condition || "true"}\` evaluates true against the runtime subject/resource/environment.`,
    roles.length ? `Role condition mentions ${formatInlineList(roles)}; indexed subjects with those roles: ${formatInlineList(subjects)}.` : "",
    subjectTypesMentionedInCondition(d.condition).length ? `Subject type condition targets ${formatInlineList(subjectTypesMentionedInCondition(d.condition))}.` : "",
    `Priority is \`${d.priority || "0"}\`; higher priority policies are considered first within policy evaluation.`,
    d.effect === "deny" ? "Because this is a deny policy, a match overrides allow grants from policies, ACLs, or roles." : "A matching deny policy or deny ACL can still override this allow.",
    broadPattern([...d.actions, ...d.resources]) ? "Warning: this policy contains a wildcard, so its blast radius is broad." : ""
  ]);
}

function hoverForRoleEntry(entry, index) {
  const d = entry.details;
  const inherited = resolveRolePermissions(entry.id, index);
  const members = index.entries.filter((item) => item.directive === "member" && item.details.role === entry.id).map((item) => item.details.subject);
  const childRoles = index.entries.filter((item) => item.directive === "role" && item.details.inherits.includes(entry.id)).map((item) => item.id);
  const policies = index.entries.filter((item) => item.directive === "policy" && rolesMentionedInCondition(item.details.condition).includes(entry.id)).map((item) => `${item.id}:${item.details.effect}`);
  return behaviorHover(`Role \`${entry.id}\` intrinsic behavior`, [
    `Direct permissions: ${formatInlineList(d.permissions)}.`,
    d.inherits.length ? `Inherits roles: ${formatInlineList(d.inherits)}.` : "Does not inherit another role.",
    childRoles.length ? `Child roles inheriting this role: ${formatInlineList(childRoles)}.` : "",
    inherited.length > d.permissions.length ? `Effective permissions including inheritance: ${formatInlineList(inherited)}.` : "",
    d.owner.length ? `Owner-scoped actions: ${formatInlineList(d.owner)}.` : "",
    members.length ? `Assigned subjects in this config: ${formatInlineList(members)}.` : "No role memberships reference this role in the indexed config.",
    policies.length ? `Policies that check this role through ABAC: ${formatInlineList(policies)}.` : "",
    broadPattern(inherited) ? "Warning: this role grants wildcard permissions; explicit denies can still override them." : ""
  ]);
}

function hoverForACLEntry(entry) {
  const d = entry.details;
  const effectText = d.effect === "deny" ? "denies" : "allows";
  return behaviorHover(`ACL \`${entry.id}\` intrinsic behavior`, [
    `Explicitly ${effectText} subject \`${d.subject}\` to perform ${formatInlineList(d.actions)} on \`${d.resource}\`.`,
    d.effect === "deny" ? "A matching deny ACL wins over matching allow ACLs, policies, or RBAC grants." : "A matching deny ACL or deny policy can still override this allow.",
    d.expires ? `Expires at \`${d.expires}\`.` : "No expiration is set.",
    broadPattern([d.resource, ...d.actions]) ? "Warning: this ACL contains a wildcard and may affect many requests." : ""
  ]);
}

function hoverForTenantEntry(entry, index) {
  const children = index.entries.filter((item) => item.directive === "tenant" && item.details.parent === entry.id).map((item) => item.id);
  const policies = index.entries.filter((item) => item.directive === "policy" && item.details.tenant === entry.id).map((item) => item.id);
  const roles = index.entries.filter((item) => item.directive === "role" && item.details.tenant === entry.id).map((item) => item.id);
  return behaviorHover(`Tenant \`${entry.id}\` intrinsic behavior`, [
    entry.details.parent ? `Parent tenant: \`${entry.details.parent}\`.` : "Root tenant or no parent declared.",
    children.length ? `Child tenants: ${formatInlineList(children)}.` : "No child tenants in the indexed config.",
    policies.length ? `Policies loaded in this tenant: ${formatInlineList(policies)}.` : "No policies directly in this tenant.",
    roles.length ? `Roles loaded in this tenant: ${formatInlineList(roles)}.` : "No roles directly in this tenant.",
    "Tenant hierarchy can affect ancestor/cross-tenant checks where the engine uses the tenant resolver."
  ]);
}

function hoverForBoundaryEntry(entry) {
  const d = entry.details;
  return behaviorHover(`Boundary \`${entry.id}\` intrinsic behavior`, [
    `Caps permissions to actions ${formatInlineList(d.actions)} on resources ${formatInlineList(d.resources)}.`,
    "Permission boundaries filter effective permissions; they do not create grants by themselves.",
    broadPattern([...d.actions, ...d.resources]) ? "This boundary includes wildcards, so it is permissive for those dimensions." : ""
  ]);
}

function hoverForRoleReference(roleID, index) {
  const entry = findEntry(index, "role", roleID);
  if (!entry) {
    return explanationHover("Role reference", "Assigns or references a role.", "No matching role definition was found in the indexed config.", `Referenced role: \`${roleID}\`.`);
  }
  return hoverForRoleEntry(entry, index);
}

function subjectBehaviorLines(subject, index) {
  const memberships = index.entries.filter((entry) => entry.directive === "member" && entry.details.subject === subject);
  const acls = index.entries.filter((entry) => entry.directive === "acl" && entry.details.subject === subject);
  const roles = unique(memberships.map((entry) => entry.details.role));
  const inferredPolicies = policiesImpliedForSubject(subject, roles, index);
  const lines = [];
  if (memberships.length) {
    const perms = unique(roles.flatMap((role) => resolveRolePermissions(role, index)));
    lines.push(`Role memberships in this config: ${formatInlineList(roles)}.`);
    if (perms.length) lines.push(`Effective RBAC permissions from those roles: ${formatInlineList(perms)}.`);
  }
  if (acls.length) {
    lines.push(`Matching explicit ACL entries: ${formatInlineList(acls.map((entry) => `${entry.id}:${entry.details.effect}`))}.`);
    lines.push(`ACL result surface: ${formatInlineList(acls.map((entry) => `${entry.details.effect} ${entry.details.actions.join(",")} on ${entry.details.resource}`))}.`);
  }
  if (inferredPolicies.length) {
    lines.push(`Policies likely to match this subject from type/roles: ${formatInlineList(inferredPolicies.map((item) => `${item.entry.id}:${item.entry.details.effect}`))}.`);
    lines.push(`Policy result surface: ${formatInlineList(inferredPolicies.map((item) => `${item.entry.details.effect} ${item.entry.details.actions.join(",")} on ${item.entry.details.resources.join(",")} (${item.reason})`))}.`);
  }
  if (!memberships.length && !acls.length && !inferredPolicies.length) {
    lines.push("No direct role memberships, matching policy conditions, or ACLs for this subject were found in the indexed config.");
  }
  return lines;
}

function permissionBehaviorLines(permissions, index) {
  const roleMatches = index.entries.filter((entry) => {
    if (entry.directive !== "role") return false;
    const effective = resolveRolePermissions(entry.id, index);
    return permissions.some((permission) => effective.some((candidate) => permissionCovers(candidate, permission) || permissionCovers(permission, candidate)));
  });
  const subjects = unique(roleMatches.flatMap((role) => {
    return index.entries.filter((entry) => entry.directive === "member" && entry.details.role === role.id).map((entry) => entry.details.subject);
  }));
  const policyMatches = index.entries.filter((entry) => {
    if (entry.directive !== "policy") return false;
    return permissions.some((permission) => permissionOverlapsPolicy(permission, entry.details));
  });
  const aclMatches = index.entries.filter((entry) => {
    if (entry.directive !== "acl") return false;
    return permissions.some((permission) => permissionOverlapsACL(permission, entry.details));
  });
  const lines = [];
  if (roleMatches.length) lines.push(`Roles whose effective permissions include/overlap this: ${formatInlineList(roleMatches.map((entry) => entry.id))}.`);
  if (subjects.length) lines.push(`Subjects receiving it through those roles: ${formatInlineList(subjects)}.`);
  if (policyMatches.length) lines.push(`Policies with overlapping action/resource surfaces: ${formatInlineList(policyMatches.map((entry) => `${entry.id}:${entry.details.effect}`))}.`);
  if (aclMatches.length) lines.push(`ACLs with overlapping action/resource surfaces: ${formatInlineList(aclMatches.map((entry) => `${entry.id}:${entry.details.effect}`))}.`);
  return lines;
}

function policiesImpliedForSubject(subject, roles, index) {
  const out = [];
  for (const entry of index.entries) {
    if (entry.directive !== "policy") continue;
    const reason = conditionMatchesSubject(entry.details.condition, subject, roles);
    if (reason) out.push({ entry, reason });
  }
  return out;
}

function conditionMatchesSubject(condition, subject, roles) {
  if (!condition || condition === "true") return "condition is always true";
  const subjectTypeValue = subjectType(subject);
  const roleMatches = rolesMentionedInCondition(condition).filter((role) => roles.includes(role));
  if (roleMatches.length) return `role match ${roleMatches.join(",")}`;
  if (subjectTypeValue && subjectTypesMentionedInCondition(condition).includes(subjectTypeValue)) return `subject.type=${subjectTypeValue}`;
  if (condition.includes("resource.owner_id=subject.id")) return "matches only resources owned by this subject";
  if (condition.includes("resource.owner_id==subject.id")) return "matches only resources owned by this subject";
  return "";
}

function rolesMentionedInCondition(condition) {
  if (!condition) return [];
  const roles = [];
  const regex = /subject\.roles@([A-Za-z0-9_.@,-]+)/g;
  let match;
  while ((match = regex.exec(condition))) {
    roles.push(...splitList(match[1]));
  }
  return unique(roles);
}

function subjectTypesMentionedInCondition(condition) {
  if (!condition) return [];
  const types = [];
  const regex = /subject\.type(?:=|==)([A-Za-z0-9_.@-]+)/g;
  let match;
  while ((match = regex.exec(condition))) {
    types.push(match[1]);
  }
  return unique(types);
}

function subjectsWithRoles(roles, index) {
  return unique(index.entries.filter((entry) => entry.directive === "member" && roles.includes(entry.details.role)).map((entry) => entry.details.subject));
}

function subjectType(subject) {
  if (subject === "guest") return "guest";
  if (subject.startsWith("user:")) return "user";
  if (subject.startsWith("group:")) return "group";
  if (subject.startsWith("service:")) return "service";
  return "";
}

function permissionOverlapsPolicy(permission, details) {
  const parsed = parsePermission(permission);
  if (!parsed) return false;
  return details.actions.some((action) => patternCovers(action, parsed.action) || patternCovers(parsed.action, action)) &&
    details.resources.some((resource) => patternCovers(resource, parsed.resource) || patternCovers(parsed.resource, resource));
}

function permissionOverlapsACL(permission, details) {
  const parsed = parsePermission(permission);
  if (!parsed) return false;
  return details.actions.some((action) => patternCovers(action, parsed.action) || patternCovers(parsed.action, action)) &&
    (patternCovers(details.resource, parsed.resource) || patternCovers(parsed.resource, details.resource));
}

function permissionCovers(grant, requested) {
  const left = parsePermission(grant);
  const right = parsePermission(requested);
  if (!left || !right) return false;
  return patternCovers(left.action, right.action) && patternCovers(left.resource, right.resource);
}

function parsePermission(permission) {
  if (permission === "*:*") return { action: "*", resource: "*" };
  const idx = permission.indexOf(":");
  if (idx <= 0) return undefined;
  return { action: permission.slice(0, idx), resource: permission.slice(idx + 1) };
}

function patternCovers(pattern, value) {
  if (pattern === "*" || pattern === value) return true;
  if (!pattern || !value) return false;
  if (pattern.endsWith(":*")) return value === pattern.slice(0, -2) || value.startsWith(pattern.slice(0, -1));
  if (pattern.endsWith("*")) return value.startsWith(pattern.slice(0, -1));
  return false;
}

function relatedResourceLines(patterns, index) {
  const relatedPolicies = index.entries.filter((entry) => entry.directive === "policy" && entry.details.resources.some((resource) => patterns.includes(resource)));
  const relatedACLs = index.entries.filter((entry) => entry.directive === "acl" && patterns.includes(entry.details.resource));
  const relatedRoles = index.entries.filter((entry) => entry.directive === "role" && entry.details.permissions.some((perm) => {
    const idx = perm.indexOf(":");
    return idx > 0 && patterns.includes(perm.slice(idx + 1));
  }));
  const lines = [];
  if (relatedPolicies.length) lines.push(`Policies using this resource pattern: ${formatInlineList(relatedPolicies.map((entry) => `${entry.id}:${entry.details.effect}`))}.`);
  if (relatedACLs.length) lines.push(`ACLs using this resource pattern: ${formatInlineList(relatedACLs.map((entry) => `${entry.id}:${entry.details.effect}`))}.`);
  if (relatedRoles.length) lines.push(`Roles granting this resource pattern: ${formatInlineList(relatedRoles.map((entry) => entry.id))}.`);
  return lines;
}

function findEntry(index, directive, id) {
  return index.entries.find((entry) => entry.directive === directive && entry.id === id);
}

function resolveRolePermissions(roleID, index, seen = new Set()) {
  if (seen.has(roleID)) return [];
  seen.add(roleID);
  const role = findEntry(index, "role", roleID);
  if (!role) return [];
  const out = [...role.details.permissions];
  for (const parent of role.details.inherits || []) {
    out.push(...resolveRolePermissions(parent, index, seen));
  }
  return unique(out);
}

function formatInlineList(values) {
  const clean = unique(values || []);
  if (clean.length === 0) return "`<none>`";
  return clean.map((value) => `\`${value}\``).join(", ");
}

function broadPattern(values) {
  return (values || []).some((value) => value === "*" || value === "*:*" || value.startsWith("*:") || value.endsWith(":*"));
}

function entryForKey(index, key) {
  const locations = index.definitions.get(key);
  if (!locations || locations.length === 0) return undefined;
  const loc = locations[0];
  return index.entries.find((entry) => entry.selectionRange.isEqual(loc.range));
}

function isDefinitionDirective(directive) {
  return ["tenant", "policy", "role", "acl", "user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive);
}

function provideDocumentSymbols(document) {
  const index = buildDocumentIndex(document);
  return index.entries.map((entry) => new vscode.DocumentSymbol(
    entry.id,
    entry.directive,
    symbolKind(entry.directive),
    entry.range,
    entry.selectionRange
  ));
}

async function provideReferences(document, position) {
  const target = await referenceTarget(document, position);
  if (!target) return undefined;
  const index = await buildWorkspaceIndex(document);
  return findReferenceLocations(index, target);
}

async function prepareRename(document, position) {
  const target = await referenceTarget(document, position);
  if (!target || !target.renameable) return undefined;
  return target.range;
}

async function provideRenameEdits(document, position, newName) {
  const target = await referenceTarget(document, position);
  if (!target || !target.renameable) return undefined;
  if (!/^[A-Za-z0-9_.@-]+$/.test(newName)) {
    throw new Error("AuthZ IDs can contain letters, numbers, underscore, dot, at-sign, and hyphen.");
  }
  const index = await buildWorkspaceIndex(document);
  const edit = new vscode.WorkspaceEdit();
  for (const ref of findReferenceRanges(index, target)) {
    edit.replace(ref.uri, ref.range, ref.prefix ? `${ref.prefix}${newName}` : newName);
  }
  return edit;
}

function provideDocumentLinks(document) {
  const links = [];
  for (let lineNo = 0; lineNo < document.lineCount; lineNo++) {
    const parsed = parseLine(document.lineAt(lineNo).text);
    if (parsed.tokens[0] !== "include" || !parsed.tokens[1]) continue;
    const includePath = unquote(parsed.tokens[1]);
    const target = path.isAbsolute(includePath) ? includePath : path.join(path.dirname(document.uri.fsPath), includePath);
    const token = parsed.tokenInfos[1];
    links.push(new vscode.DocumentLink(
      new vscode.Range(lineNo, token.start - 1 >= 0 ? token.start - 1 : token.start, lineNo, token.end + 1),
      vscode.Uri.file(target)
    ));
  }
  return links;
}

function provideCodeActions(document, range, context) {
  const actionsOut = [];
  for (const diagnostic of context.diagnostics) {
    if (/Unknown AuthZ directive/.test(diagnostic.message)) {
      const replacement = nearestDirective(document.getText(diagnostic.range));
      if (replacement) {
        const action = new vscode.CodeAction(`Change to '${replacement}'`, vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(document.uri, diagnostic.range, replacement);
        action.diagnostics = [diagnostic];
        actionsOut.push(action);
      }
    }
    if (/Effect must be allow or deny/.test(diagnostic.message)) {
      for (const effect of effects) {
        const action = new vscode.CodeAction(`Change effect to '${effect}'`, vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(document.uri, diagnostic.range, effect);
        action.diagnostics = [diagnostic];
        actionsOut.push(action);
      }
    }
  }
  return actionsOut;
}

function validateDocument(document) {
  const diagnostics = [];
  const seen = { tenant: new Set(), policy: new Set(), role: new Set(), acl: new Set(), user: new Set(), group: new Set(), scope: new Set() };

  for (let lineNo = 0; lineNo < document.lineCount; lineNo++) {
    const text = document.lineAt(lineNo).text;
    const parsed = parseLine(text);
    if (parsed.error) {
      diagnostics.push(diag(lineNo, 0, text.length, parsed.error, vscode.DiagnosticSeverity.Error));
      continue;
    }
    const tokens = parsed.tokens;
    if (tokens.length === 0) continue;
    const directive = tokens[0];
    const rangeEnd = Math.max(1, directive.length);
    const startsBlock = isBlockHeader(tokens);
    if (!directiveDocs.has(directive)) {
      diagnostics.push(diag(lineNo, 0, rangeEnd, `Unknown AuthZ directive "${directive}".`, vscode.DiagnosticSeverity.Error));
      continue;
    }
    if (startsBlock) {
      checkDuplicateIds(document, diagnostics, lineNo, tokens, seen);
      const block = collectDocumentBlock(document, lineNo);
      checkBlock(document, diagnostics, lineNo, block.end, tokens);
      lineNo = block.end;
      continue;
    }
    checkArity(document, diagnostics, lineNo, text, tokens);
    checkOptions(document, diagnostics, lineNo, text, tokens);
    checkValues(document, diagnostics, lineNo, text, tokens);
    checkDuplicateIds(document, diagnostics, lineNo, tokens, seen);
  }
  return diagnostics;
}

function checkArity(document, diagnostics, lineNo, text, tokens) {
  const required = { include: 2, tenant: 3, policy: 7, role: 5, acl: 6, member: 3, engine: 1, user: 5, group: 4, scope: 4, service_account: 4, invitation: 5, api_key: 6, boundary: 6 };
  const need = required[tokens[0]];
  if (need !== undefined && tokens.length < need) {
    diagnostics.push(diag(lineNo, 0, text.length, `${tokens[0]} requires ${need - 1} argument(s).`, vscode.DiagnosticSeverity.Warning));
  }
}

function checkOptions(document, diagnostics, lineNo, text, tokens) {
  const directive = tokens[0];
  const allowed = new Set((optionsByDirective[directive] || []).map(([x]) => x));
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (directive === "engine") {
      if (token.includes("=") && !engineOptions.some(([opt]) => token.startsWith(opt))) {
        diagnostics.push(rangeDiag(document, lineNo, token, `Unknown engine option "${token.split("=")[0]}".`, vscode.DiagnosticSeverity.Error));
      }
      continue;
    }
    if (isPositionalToken(directive, i)) continue;
    const colon = token.indexOf(":");
    if (colon === -1) continue;
    const prefix = token.slice(0, colon + 1);
    if (isResourceLike(token) || isSubjectLike(token) || isPermissionLike(token)) continue;
    if (allowed.size > 0 && !allowed.has(prefix)) {
      diagnostics.push(rangeDiag(document, lineNo, token, `Unknown ${directive} option "${prefix}".`, vscode.DiagnosticSeverity.Error));
    }
  }
}

function checkBlock(document, diagnostics, startLine, endLine, headerTokens) {
  const directive = headerTokens[0];
  const allowed = new Set(blockFieldsByDirective[directive] || []);
  const seenFields = new Set();
  let activeList = "";
  let activeNested = "";

  if (directive !== "members" && directive !== "engine" && headerTokens.length !== 3) {
    diagnostics.push(diag(startLine, 0, document.lineAt(startLine).text.length, `${directive} block requires exactly one id before "{".`, vscode.DiagnosticSeverity.Error));
  }
  if ((directive === "members" || directive === "engine") && headerTokens.length !== 2) {
    diagnostics.push(diag(startLine, 0, document.lineAt(startLine).text.length, `${directive} block does not take an id.`, vscode.DiagnosticSeverity.Error));
  }

  for (let lineNo = startLine + 1; lineNo <= endLine; lineNo++) {
    const text = document.lineAt(lineNo).text;
    const parsed = parseLine(text);
    const tokens = parsed.tokens;
    if (parsed.error) {
      diagnostics.push(diag(lineNo, 0, text.length, parsed.error, vscode.DiagnosticSeverity.Error));
      continue;
    }
    if (tokens.length === 0) continue;
    if (tokens.length === 1 && tokens[0] === "]") {
      activeList = "";
      continue;
    }
    if (tokens.length === 1 && tokens[0] === "}") {
      activeNested = "";
      continue;
    }
    if (directive === "members") {
      checkMembersBlockRow(document, diagnostics, lineNo, tokens);
      continue;
    }

    const field = activeList || activeNested || tokens[0];
    const valueTokens = activeList || activeNested ? tokens : tokens.slice(1);

    if (!activeList && !activeNested) {
      if (allowed.size && !allowed.has(field)) {
        diagnostics.push(rangeDiag(document, lineNo, field, `Unknown ${directive} block field "${field}".`, vscode.DiagnosticSeverity.Error));
      }
      seenFields.add(field);
      if (tokens[1] === "[") {
        activeList = field;
        continue;
      }
      if (tokens[1] === "{") {
        activeNested = field;
        continue;
      }
    }

    checkBlockFieldValues(document, diagnostics, lineNo, directive, field, valueTokens);
  }

  for (const field of requiredBlockFields[directive] || []) {
    if (!seenFields.has(field)) {
      diagnostics.push(diag(startLine, 0, document.lineAt(startLine).text.length, `${directive} block is missing required field "${field}".`, vscode.DiagnosticSeverity.Warning));
    }
  }
}

function checkMembersBlockRow(document, diagnostics, lineNo, tokens) {
  if (tokens.length < 2) {
    diagnostics.push(diag(lineNo, 0, document.lineAt(lineNo).text.length, `members rows require: <subject> [roles].`, vscode.DiagnosticSeverity.Warning));
    return;
  }
  if (!isSubjectLike(tokens[0])) {
    diagnostics.push(rangeDiag(document, lineNo, tokens[0], `Member subject should be namespaced like user:alice, group:engineering, service:worker, guest, or *.`, vscode.DiagnosticSeverity.Warning));
  }
}

function checkBlockFieldValues(document, diagnostics, lineNo, directive, field, values) {
  const cleanValues = values.map(cleanBlockValue).filter((value) => value && value !== "[" && value !== "]" && value !== "{");
  if ((field === "effect") && cleanValues[0] && !effects.includes(cleanValues[0])) {
    diagnostics.push(rangeDiag(document, lineNo, cleanValues[0], `Effect must be allow or deny.`, vscode.DiagnosticSeverity.Error));
  }
  if (field === "permissions") {
    for (const perm of cleanValues) {
      if (perm !== "*:*" && !isPermissionLike(perm)) {
        diagnostics.push(rangeDiag(document, lineNo, perm, `Role permissions must use action:resource syntax.`, vscode.DiagnosticSeverity.Error));
      }
    }
  }
  if (field === "expires" && cleanValues[0] && Number.isNaN(Date.parse(cleanValues[0]))) {
    diagnostics.push(rangeDiag(document, lineNo, cleanValues[0], `expires must be an RFC3339 timestamp.`, vscode.DiagnosticSeverity.Error));
  }
  if (directive === "engine" && field && !engineOptions.some(([opt]) => opt.slice(0, -1) === field)) {
    diagnostics.push(rangeDiag(document, lineNo, field, `Unknown engine option "${field}".`, vscode.DiagnosticSeverity.Error));
  }
  for (const value of cleanValues) {
    if (value.includes(",,")) {
      diagnostics.push(rangeDiag(document, lineNo, value, `Lists cannot contain empty items.`, vscode.DiagnosticSeverity.Error));
    }
  }
}

function isPositionalToken(directive, index) {
  const positionalThrough = {
    include: 1,
    tenant: 2,
    policy: 6,
    role: 4,
    acl: 5,
    member: 2,
    user: 4,
    group: 3,
    scope: 3,
    service_account: 3,
    invitation: 4,
    api_key: 5,
    boundary: 5
  };
  return index <= (positionalThrough[directive] || 0);
}

function checkValues(document, diagnostics, lineNo, text, tokens) {
  const directive = tokens[0];
  if ((directive === "policy" && tokens[3] && !effects.includes(tokens[3])) || (directive === "acl" && tokens[5] && !effects.includes(tokens[5]))) {
    const token = directive === "policy" ? tokens[3] : tokens[5];
    diagnostics.push(rangeDiag(document, lineNo, token, `Effect must be allow or deny.`, vscode.DiagnosticSeverity.Error));
  }
  if (directive === "role" && tokens[4]) {
    for (const perm of tokens[4].split(",")) {
      if (perm !== "*:*" && !isPermissionLike(perm)) {
        diagnostics.push(rangeDiag(document, lineNo, perm, `Role permissions must use action:resource syntax.`, vscode.DiagnosticSeverity.Error));
      }
    }
  }
  for (const token of tokens) {
    if (token.includes(",,")) {
      diagnostics.push(rangeDiag(document, lineNo, token, `Lists cannot contain empty items.`, vscode.DiagnosticSeverity.Error));
    }
    if (token.startsWith("expires:") && token.length > "expires:".length && Number.isNaN(Date.parse(token.slice(8)))) {
      diagnostics.push(rangeDiag(document, lineNo, token, `expires must be an RFC3339 timestamp.`, vscode.DiagnosticSeverity.Error));
    }
  }
}

function checkDuplicateIds(document, diagnostics, lineNo, tokens, seen) {
  const directive = tokens[0];
  if (!seen[directive] || !tokens[1]) return;
  const id = unquote(tokens[1]);
  if (seen[directive].has(id)) {
    diagnostics.push(rangeDiag(document, lineNo, tokens[1], `Duplicate ${directive} ID "${id}" in this file.`, vscode.DiagnosticSeverity.Warning));
  }
  seen[directive].add(id);
}

function formatDocument(document) {
  const edits = [];
  const lines = [];
  for (let i = 0; i < document.lineCount; i++) {
    const original = document.lineAt(i).text;
    if (/^\s*#/.test(original) || original.trim() === "") {
      lines.push(original.trimEnd());
      continue;
    }
    lines.push(original.replace(/\s+#/, " #").trim());
  }
  const fullRange = new vscode.Range(0, 0, document.lineCount, 0);
  edits.push(vscode.TextEdit.replace(fullRange, lines.join("\n")));
  return edits;
}

function buildDocumentIndex(document) {
  const index = {
    tenants: [],
    policies: [],
    roles: [],
    acls: [],
    members: [],
    users: [],
    groups: [],
    scopes: [],
    serviceAccounts: [],
    invitations: [],
    apiKeys: [],
    boundaries: [],
    subjects: [],
    actions: [],
    resources: [],
    definitions: new Map(),
    entries: []
  };
  indexLines(index, Array.from({ length: document.lineCount }, (_, i) => document.lineAt(i).text), document.uri, (line) => document.lineAt(line).range);
  index.tenants = unique(index.tenants);
  index.policies = unique(index.policies);
  index.roles = unique(index.roles);
  index.acls = unique(index.acls);
  index.members = unique(index.members);
  index.users = unique(index.users);
  index.groups = unique(index.groups);
  index.scopes = unique(index.scopes);
  index.serviceAccounts = unique(index.serviceAccounts);
  index.invitations = unique(index.invitations);
  index.apiKeys = unique(index.apiKeys);
  index.boundaries = unique(index.boundaries);
  index.subjects = unique(index.subjects);
  index.actions = unique(index.actions);
  index.resources = unique(index.resources);
  return index;
}

async function buildWorkspaceIndex(document) {
  const root = workspaceRoot(document);
  const index = emptyIndex();
  const seen = new Set();
  const docs = new Map();

  for (const doc of vscode.workspace.textDocuments) {
    if (doc.languageId === "authz" || /\.(authz|dsl)$/i.test(doc.uri.fsPath)) {
      docs.set(doc.uri.fsPath, doc.getText());
    }
  }
  if (document) docs.set(document.uri.fsPath, document.getText());

  if (root) {
    const files = await vscode.workspace.findFiles("**/*.{authz,dsl}", "**/{node_modules,.git}/**", 500);
    for (const uri of files) {
      if (!docs.has(uri.fsPath)) {
        try {
          docs.set(uri.fsPath, fs.readFileSync(uri.fsPath, "utf8"));
        } catch {
          // Ignore unreadable workspace files.
        }
      }
    }
  }

  for (const [file, text] of docs) {
    mergeIndex(index, buildTextIndex(text, vscode.Uri.file(file), seen));
  }
  finalizeIndex(index);
  return index;
}

function buildTextIndex(text, uri, seen) {
  const index = emptyIndex();
  const key = uri.fsPath;
  if (seen.has(key)) return index;
  seen.add(key);

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLine(lines[i]);
    const tokens = parsed.tokens;
    if (tokens.length < 1) continue;
    if (tokens[0] === "include" && tokens[1]) {
      const includePath = unquote(tokens[1]);
      const target = path.isAbsolute(includePath) ? includePath : path.join(path.dirname(uri.fsPath), includePath);
      if (fs.existsSync(target)) {
        try {
          mergeIndex(index, buildTextIndex(fs.readFileSync(target, "utf8"), vscode.Uri.file(target), seen));
        } catch {
          // Ignore include read failures; CLI validation reports them.
        }
      }
      continue;
    }
  }
  indexLines(index, lines, uri, (line) => new vscode.Range(line, 0, line, lines[line].length), true);
  return index;
}

function emptyIndex() {
  return {
    tenants: [],
    policies: [],
    roles: [],
    acls: [],
    members: [],
    users: [],
    groups: [],
    scopes: [],
    serviceAccounts: [],
    invitations: [],
    apiKeys: [],
    boundaries: [],
    subjects: [],
    actions: [],
    resources: [],
    definitions: new Map(),
    references: [],
    entries: []
  };
}

function mergeIndex(target, source) {
  for (const key of ["tenants", "policies", "roles", "acls", "members", "users", "groups", "scopes", "serviceAccounts", "invitations", "apiKeys", "boundaries", "subjects", "actions", "resources", "references", "entries"]) {
    target[key].push(...source[key]);
  }
  for (const [key, locations] of source.definitions) {
    if (!target.definitions.has(key)) target.definitions.set(key, []);
    target.definitions.get(key).push(...locations);
  }
}

function finalizeIndex(index) {
  for (const key of ["tenants", "policies", "roles", "acls", "members", "users", "groups", "scopes", "serviceAccounts", "invitations", "apiKeys", "boundaries", "subjects", "actions", "resources"]) {
    index[key] = unique(index[key]);
  }
}

function indexLines(index, lines, uri, rangeForLine, collectRefs = false) {
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLine(lines[i]);
    const tokens = parsed.tokens;
    if (tokens.length < 1) continue;
    if (isBlockHeader(tokens)) {
      const block = collectBlockLines(lines, i);
      addBlockEntries(index, uri, lines, i, block.end, parsed, block.body, rangeForLine, collectRefs);
      i = block.end;
      continue;
    }
    addInlineEntry(index, uri, lines, i, parsed, rangeForLine, collectRefs);
  }
}

function addInlineEntry(index, uri, lines, i, parsed, rangeForLine, collectRefs) {
  const tokens = parsed.tokens;
  if (tokens.length < 2) return;
  const directive = tokens[0];
  const id = unquote(tokens[1]);
  const idInfo = parsed.tokenInfos[1];
  if (!idInfo) return;
  const selectionRange = new vscode.Range(i, idInfo.start, i, idInfo.end);
  const range = rangeForLine(i);
  addEntryForDirective(index, directive, id, uri, range, selectionRange, parseEntryDetails(tokens));
  collectActionsAndResources(index, tokens);
  if (collectRefs) collectReferences(index, uri, i, parsed);
}

function addBlockEntries(index, uri, lines, start, end, parsed, body, rangeForLine, collectRefs) {
  const tokens = parsed.tokens;
  const directive = tokens[0];
  const range = new vscode.Range(start, 0, end, lines[end] ? lines[end].length : lines[start].length);
  if (directive === "members") {
    for (const row of body) {
      const rowParsed = parseLine(lines[row.line]);
      if (rowParsed.tokens.length < 2) continue;
      const subject = rowParsed.tokens[0];
      const roles = parseBlockValues(rowParsed.tokens.slice(1));
      const subjectInfo = rowParsed.tokenInfos[0];
      const selectionRange = new vscode.Range(row.line, subjectInfo.start, row.line, subjectInfo.end);
      for (const role of roles) {
        const details = { subject, role };
        addEntry(index, "members", "member", `${subject} -> ${role}`, uri, rangeForLine(row.line), selectionRange, [], details);
        if (collectRefs) {
          index.references.push({ key: subject, uri, range: selectionRange, value: subject, prefix: "" });
          addListReference(index, uri, row.line, lines[row.line], role, "role");
        }
      }
    }
    return;
  }
  if (tokens.length < 2) return;
  const id = unquote(tokens[1]);
  const idInfo = parsed.tokenInfos[1];
  if (!idInfo) return;
  const selectionRange = new vscode.Range(start, idInfo.start, start, idInfo.end);
  const details = parseBlockEntryDetails(directive, body.map((item) => lines[item.line]));
  if (directive === "member") {
    details.subject = id;
    for (const role of details.roles || []) {
      addEntry(index, "members", "member", `${id} -> ${role}`, uri, range, selectionRange, [], { subject: id, role, roles: details.roles });
      if (collectRefs) addListReference(index, uri, start, lines[start], id, "");
    }
    return;
  }
  addEntryForDirective(index, directive, id, uri, range, selectionRange, details);
  collectBlockActionsAndResources(index, directive, details);
  if (collectRefs) collectBlockReferences(index, uri, body, lines, directive, details);
}

function addEntryForDirective(index, directive, id, uri, range, selectionRange, details) {
  if (directive === "tenant") addEntry(index, "tenants", "tenant", id, uri, range, selectionRange, [id], details);
  if (directive === "policy") addEntry(index, "policies", "policy", id, uri, range, selectionRange, [id, `policy:${id}`], details);
  if (directive === "role") addEntry(index, "roles", "role", id, uri, range, selectionRange, [id, `role:${id}`], details);
  if (directive === "acl") addEntry(index, "acls", "acl", id, uri, range, selectionRange, [id, `acl:${id}`], details);
  if (directive === "member" && details.role) addEntry(index, "members", "member", `${details.subject} -> ${details.role}`, uri, range, selectionRange, [], details);
  if (directive === "user") addEntry(index, "users", "user", id, uri, range, selectionRange, [id, `user:${id}`], details);
  if (directive === "group") addEntry(index, "groups", "group", id, uri, range, selectionRange, [id, `group:${id}`], details);
  if (directive === "scope") addEntry(index, "scopes", "scope", id, uri, range, selectionRange, [id, `scope:${id}`], details);
  if (directive === "service_account") addEntry(index, "serviceAccounts", "service_account", id, uri, range, selectionRange, [id, `service:${id}`, `service_account:${id}`], details);
  if (directive === "invitation") addEntry(index, "invitations", "invitation", id, uri, range, selectionRange, [id, `invitation:${id}`], details);
  if (directive === "api_key") addEntry(index, "apiKeys", "api_key", id, uri, range, selectionRange, [id, `api_key:${id}`], details);
  if (directive === "boundary") addEntry(index, "boundaries", "boundary", id, uri, range, selectionRange, [id, `boundary:${id}`], details);
}

function collectBlockLines(lines, start) {
  let depth = braceDelta(lines[start]);
  const body = [];
  let end = start;
  for (let i = start + 1; i < lines.length; i++) {
    const oldDepth = depth;
    depth += braceDelta(lines[i]);
    const parsed = parseLine(lines[i]);
    if (!(oldDepth === 1 && depth === 0 && parsed.tokens.length === 1 && parsed.tokens[0] === "}")) {
      body.push({ line: i });
    }
    end = i;
    if (depth <= 0) break;
  }
  return { body, end };
}

function parseBlockEntryDetails(directive, bodyLines) {
  const fields = parseBlockFields(bodyLines);
  if (directive === "tenant") return { name: first(fields.values.name), parent: first(fields.values.parent) || "" };
  if (directive === "policy") {
    return {
      tenant: first(fields.values.tenant),
      effect: first(fields.values.effect),
      actions: fields.values.actions || [],
      resources: fields.values.resources || [],
      condition: fields.blocks.when || fields.blocks.condition || first(fields.values.condition) || "true",
      priority: first(fields.values.priority) || "0"
    };
  }
  if (directive === "role") {
    return {
      tenant: first(fields.values.tenant),
      name: first(fields.values.name),
      permissions: fields.values.permissions || [],
      inherits: fields.values.inherits || [],
      owner: fields.values.owner_actions || []
    };
  }
  if (directive === "acl") {
    return {
      resource: first(fields.values.resource),
      subject: first(fields.values.subject),
      actions: fields.values.actions || [],
      effect: first(fields.values.effect),
      expires: first(fields.values.expires) || ""
    };
  }
  if (directive === "member") {
    const roles = fields.values.roles || [];
    return { subject: "", role: roles[0] || "", roles };
  }
  return { tenant: first(fields.values.tenant), options: fields.values };
}

function parseBlockFields(lines) {
  const fields = { values: {}, blocks: {} };
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLine(lines[i]);
    const tokens = parsed.tokens;
    if (tokens.length === 0 || tokens[0] === "}") continue;
    const key = tokens[0];
    if (tokens[1] === "{") {
      const nested = collectBlockLines(lines, i);
      const collected = nested.body.flatMap((item) => parseLine(lines[item.line]).tokens);
      fields.blocks[key] = collected.join(" ");
      i = nested.end;
      continue;
    }
    if (tokens[1] === "[") {
      const collected = [];
      for (let j = i + 1; j < lines.length; j++) {
        const row = parseLine(lines[j]).tokens;
        if (row.length === 1 && row[0] === "]") {
          i = j;
          break;
        }
        collected.push(...row.map((part) => cleanBlockValue(part)).filter(Boolean));
      }
      fields.values[key] = (fields.values[key] || []).concat(collected);
      continue;
    }
    fields.values[key] = (fields.values[key] || []).concat(parseBlockValues(tokens.slice(1)));
  }
  return fields;
}

function parseBlockValues(tokens) {
  if (!tokens || tokens.length === 0) return [];
  if (tokens.length === 1 && !tokens[0].startsWith("[") && !tokens[0].startsWith("{")) return [unquote(tokens[0])].filter(Boolean);
  const joined = tokens.join(" ").replace(/^\[/, "").replace(/\]$/, "").replace(/,/g, " ");
  return parseLine(joined).tokens.map((item) => cleanBlockValue(item)).filter(Boolean);
}

function cleanBlockValue(value) {
  return unquote(String(value || "").replace(/^\[/, "").replace(/\]$/, "").replace(/,$/, ""));
}

function first(values) {
  return values && values.length ? values[0] : "";
}

function collectBlockActionsAndResources(index, directive, details) {
  if (directive === "policy") {
    for (const action of details.actions || []) index.actions.push(action);
    for (const resource of details.resources || []) index.resources.push(resource);
  }
  if (directive === "acl") {
    if (details.resource) index.resources.push(details.resource);
    for (const action of details.actions || []) index.actions.push(action);
  }
  if (directive === "role") {
    for (const permission of details.permissions || []) collectPermissions(index, permission);
  }
}

function collectBlockReferences(index, uri, body, lines, directive, details) {
  let activeList = "";
  for (const item of body) {
    const parsed = parseLine(lines[item.line]);
    if (parsed.tokens.length === 0) continue;
    if (parsed.tokens.length === 1 && parsed.tokens[0] === "]") {
      activeList = "";
      continue;
    }
    const startsList = parsed.tokens[1] === "[";
    const field = activeList || parsed.tokens[0];
    const firstValueIndex = activeList ? 0 : 1;
    for (let i = firstValueIndex; i < parsed.tokens.length; i++) {
      const tokenInfo = parsed.tokenInfos[i];
      if (!tokenInfo) continue;
      const keys = definitionKeysForBlockToken(directive, field, i, tokenInfo, tokenInfo.start, Boolean(activeList));
      for (const key of keys) {
        index.references.push({
          key,
          uri,
          range: new vscode.Range(item.line, tokenInfo.start, item.line, tokenInfo.end),
          value: tokenInfo.value,
          prefix: ""
        });
      }
    }
    if (startsList) activeList = parsed.tokens[0];
  }
}

function addListReference(index, uri, line, text, value, prefix) {
  const start = Math.max(0, text.indexOf(value));
  const range = new vscode.Range(line, start, line, start + value.length);
  index.references.push({ key: value, uri, range, value, prefix: "" });
  if (prefix) index.references.push({ key: `${prefix}:${value}`, uri, range, value, prefix: "" });
}

function addEntry(index, collection, directive, id, uri, range, selectionRange, keys, details = {}) {
  index[collection].push(id);
  index.entries.push({ directive, id, uri, range, selectionRange, details });
  if (directive === "user") index.subjects.push(`user:${id}`);
  if (directive === "group") index.subjects.push(`group:${id}`);
  if (directive === "service_account") index.subjects.push(`service:${id}`);
  for (const key of keys) {
    if (!index.definitions.has(key)) index.definitions.set(key, []);
    index.definitions.get(key).push(new vscode.Location(uri, selectionRange));
  }
}

function parseEntryDetails(tokens) {
  const directive = tokens[0];
  const options = {};
  for (const token of tokens.slice(2)) {
    const idx = token.indexOf(":");
    if (idx > 0) options[token.slice(0, idx)] = token.slice(idx + 1);
  }
  if (directive === "tenant") return { name: tokens[2], parent: options.parent || "" };
  if (directive === "policy") {
    return {
      tenant: tokens[2],
      effect: tokens[3],
      actions: splitList(tokens[4]),
      resources: splitList(tokens[5]),
      condition: tokens[6],
      priority: options.priority || "0"
    };
  }
  if (directive === "role") {
    return {
      tenant: tokens[2],
      name: tokens[3],
      permissions: splitList(tokens[4]),
      inherits: splitList(options.inherits),
      owner: splitList(options.owner)
    };
  }
  if (directive === "acl") {
    return {
      resource: tokens[2],
      subject: tokens[3],
      actions: splitList(tokens[4]),
      effect: tokens[5],
      expires: options.expires || ""
    };
  }
  if (directive === "member") return { subject: tokens[1], role: tokens[2] };
  if (directive === "boundary") return { tenant: tokens[2], name: tokens[3], actions: splitList(tokens[4]), resources: splitList(tokens[5]) };
  return { tenant: tokens[2], options };
}

function splitList(value) {
  if (!value) return [];
  return value.split(",").filter(Boolean);
}

function collectActionsAndResources(index, tokens) {
  const directive = tokens[0];
  if (directive === "policy") {
    collectList(index.actions, tokens[4]);
    collectList(index.resources, tokens[5]);
  }
  if (directive === "acl") {
    index.resources.push(tokens[2]);
    collectList(index.actions, tokens[4]);
  }
  if (directive === "role") {
    collectPermissions(index, tokens[4]);
  }
  if (directive === "boundary") {
    collectList(index.actions, tokens[4]);
    collectList(index.resources, tokens[5]);
  }
}

function collectList(out, value) {
  if (!value) return;
  for (const item of value.split(",")) {
    if (item) out.push(item);
  }
}

function collectPermissions(index, value) {
  if (!value) return;
  for (const item of value.split(",")) {
    const colon = item.indexOf(":");
    if (colon <= 0) continue;
    index.actions.push(item.slice(0, colon));
    index.resources.push(item.slice(colon + 1));
  }
}

function collectReferences(index, uri, line, parsed) {
  const directive = parsed.tokens[0];
  for (let i = 1; i < parsed.tokens.length; i++) {
    const tokenInfo = parsed.tokenInfos[i];
    if (!tokenInfo) continue;
    const keys = definitionKeysForToken(directive, i, tokenInfo, tokenInfo.start);
    for (const key of keys) {
      const prefix = prefixedTokenParts(tokenInfo.value);
      index.references.push({
        key,
        uri,
        range: new vscode.Range(line, tokenInfo.start, line, tokenInfo.end),
        value: tokenInfo.value,
        prefix: prefix && key.endsWith(`:${prefix.value}`) ? prefix.prefix : ""
      });
    }
    const option = optionPartsAt(tokenInfo, tokenInfo.start + tokenInfo.value.length);
    if (option && option.value) {
      const valueStart = tokenInfo.start + option.key.length;
      for (const item of option.value.split(",")) {
        if (!item) continue;
        const itemStart = tokenInfo.value.indexOf(item, option.key.length);
        index.references.push({
          key: item,
          uri,
          range: new vscode.Range(line, tokenInfo.start + itemStart, line, tokenInfo.start + itemStart + item.length),
          value: item,
          prefix: ""
        });
        if (option.key === "roles:" || option.key === "inherits:") index.references.push({ key: `role:${item}`, uri, range: new vscode.Range(line, tokenInfo.start + itemStart, line, tokenInfo.start + itemStart + item.length), value: item, prefix: "" });
        if (option.key === "groups:") index.references.push({ key: `group:${item}`, uri, range: new vscode.Range(line, tokenInfo.start + itemStart, line, tokenInfo.start + itemStart + item.length), value: item, prefix: "" });
        if (option.key === "scopes:") index.references.push({ key: `scope:${item}`, uri, range: new vscode.Range(line, tokenInfo.start + itemStart, line, tokenInfo.start + itemStart + item.length), value: item, prefix: "" });
      }
      void valueStart;
    }
  }
}

async function referenceTarget(document, position) {
  const line = document.lineAt(position.line).text;
  const parsed = parseLine(line);
  const tokenInfo = tokenAt(parsed, position.character);
  if (!tokenInfo || parsed.tokens.length === 0) return undefined;
  const tokenIndex = parsed.tokenInfos.indexOf(tokenInfo);
  const directive = parsed.tokens[0];
  const block = blockContextAt(document, position.line);
  const blockField = block ? blockFieldAt(document, block, position.line) : "";
  const blockValueToken = block ? isBlockValueLine(blockField, parsed.tokens) : false;
  const keys = block && !isBlockHeader(parsed.tokens)
    ? definitionKeysForBlockToken(block.directive, blockField || parsed.tokens[0], tokenIndex, tokenInfo, position.character, blockValueToken)
    : definitionKeysForToken(directive, tokenIndex, tokenInfo, position.character);
  const isDefinition = tokenIndex === 1 && isDefinitionDirective(directive);
  const defKeys = isDefinition ? definitionKeysForDefinition(directive, tokenInfo.value) : keys;
  const range = tokenInfo.range || new vscode.Range(position.line, tokenInfo.start, position.line, tokenInfo.end);
  return { keys: defKeys, range, renameable: isDefinition || defKeys.length > 0, value: tokenInfo.value };
}

function definitionKeysForDefinition(directive, id) {
  if (directive === "tenant") return [id];
  if (directive === "role") return [id, `role:${id}`];
  if (directive === "user") return [id, `user:${id}`];
  if (directive === "group") return [id, `group:${id}`];
  if (directive === "scope") return [id, `scope:${id}`];
  if (directive === "service_account") return [id, `service:${id}`, `service_account:${id}`];
  return [id, `${directive}:${id}`];
}

function findReferenceLocations(index, target) {
  const out = [];
  for (const key of target.keys) {
    const defs = index.definitions.get(key) || [];
    out.push(...defs);
    out.push(...index.references.filter((ref) => ref.key === key).map((ref) => new vscode.Location(ref.uri, ref.range)));
  }
  return dedupeLocations(out);
}

function findReferenceRanges(index, target) {
  const out = [];
  for (const key of target.keys) {
    const defs = index.definitions.get(key) || [];
    out.push(...defs.map((loc) => ({ uri: loc.uri, range: loc.range, prefix: "" })));
    out.push(...index.references.filter((ref) => ref.key === key));
  }
  return dedupeReferenceRanges(out);
}

function prefixedTokenParts(value) {
  const idx = value.indexOf(":");
  if (idx <= 0) return undefined;
  return { prefix: value.slice(0, idx + 1), value: value.slice(idx + 1) };
}

function dedupeLocations(locations) {
  const seen = new Set();
  return locations.filter((loc) => {
    const key = `${loc.uri.fsPath}:${loc.range.start.line}:${loc.range.start.character}:${loc.range.end.character}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dedupeReferenceRanges(refs) {
  const seen = new Set();
  return refs.filter((ref) => {
    const key = `${ref.uri.fsPath}:${ref.range.start.line}:${ref.range.start.character}:${ref.range.end.character}:${ref.prefix || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function parseLine(line) {
  const tokens = [];
  const tokenInfos = [];
  let token = "";
  let quote = "";
  let tokenStart = -1;
  let tokenEnd = -1;
  const pushToken = () => {
    if (!token) return;
    tokens.push(token);
    tokenInfos.push({ value: token, start: tokenStart, end: tokenEnd >= tokenStart ? tokenEnd : tokenStart + token.length });
    token = "";
    tokenStart = -1;
    tokenEnd = -1;
  };
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (!quote && ch === "#") break;
    if (!quote && /\s/.test(ch)) {
      pushToken();
      continue;
    }
    if ((ch === "\"" || ch === "'" || ch === "`") && (!quote || quote === ch)) {
      if (!quote && tokenStart === -1) tokenStart = i + 1;
      if (quote) {
        tokenEnd = i;
        quote = "";
      } else {
        quote = ch;
      }
      continue;
    }
    if (tokenStart === -1) tokenStart = i;
    token += ch;
    tokenEnd = i + 1;
  }
  if (quote) return { tokens, tokenInfos, error: "Unterminated quoted string." };
  pushToken();
  return { tokens, tokenInfos };
}

function isBlockHeader(tokens) {
  return tokens.length >= 2 && tokens[tokens.length - 1] === "{" && blockDirectiveNames.has(tokens[0]);
}

function braceDelta(line) {
  let quote = "";
  let delta = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
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

function blockContextAt(document, lineNo) {
  let depth = 0;
  let active;
  for (let i = 0; i < lineNo; i++) {
    const parsed = parseLine(document.lineAt(i).text);
    const delta = braceDelta(document.lineAt(i).text);
    if (isBlockHeader(parsed.tokens)) {
      active = { directive: parsed.tokens[0], start: i };
    }
    depth += delta;
    if (depth <= 0) active = undefined;
  }
  return active;
}

function blockFieldAt(document, block, lineNo) {
  if (!block) return "";
  let activeList = "";
  let activeNested = "";
  for (let i = block.start + 1; i <= lineNo; i++) {
    const parsed = parseLine(document.lineAt(i).text);
    if (parsed.tokens.length === 0) continue;
    if (parsed.tokens.length === 1 && parsed.tokens[0] === "]") {
      activeList = "";
      continue;
    }
    if (parsed.tokens.length === 1 && parsed.tokens[0] === "}") {
      activeNested = "";
      continue;
    }
    if (parsed.tokens[1] === "[") {
      activeList = parsed.tokens[0];
      if (i === lineNo) return activeList;
      continue;
    }
    if (parsed.tokens[1] === "{") {
      activeNested = parsed.tokens[0];
      if (i === lineNo) return activeNested;
      continue;
    }
    if (i === lineNo) return activeList || activeNested || parsed.tokens[0] || "";
  }
  return "";
}

function isBlockValueLine(field, tokens) {
  return Boolean(field) && tokens.length > 0 && tokens[0] !== field;
}

function collectDocumentBlock(document, start) {
  let depth = braceDelta(document.lineAt(start).text);
  let end = start;
  for (let i = start + 1; i < document.lineCount; i++) {
    depth += braceDelta(document.lineAt(i).text);
    end = i;
    if (depth <= 0) break;
  }
  return { end };
}

function inBlockConditionContext(block, field) {
  return block && block.directive === "policy" && (field === "when" || field === "condition");
}

function inConditionContext(text, parsed) {
  const directive = parsed.tokens[0];
  return directive === "policy" && parsed.tokens.length >= 7 && !/^.*\spriority:/.test(text);
}

function currentOptionValue(text) {
  const match = /(?:^|\s)([A-Za-z_][\w_]*:)([^\s]*)$/.exec(text);
  if (!match) return undefined;
  return { key: match[1], value: match[2] };
}

function expectsStatus(directive, text) {
  return ["user", "service_account", "invitation"].includes(directive) && /status:[^\s]*$/.test(text);
}

function tokenAt(parsed, character) {
  return parsed.tokenInfos.find((token) => character >= token.start && character <= token.end);
}

function definitionKeysForToken(directive, tokenIndex, tokenInfo, character) {
  const value = tokenInfo.value;
  const option = optionPartsAt(tokenInfo, character);
  if (option) return definitionKeysForOption(directive, option.key, option.value);

  if (directive === "policy" && tokenIndex === 2) return [value];
  if (directive === "role" && tokenIndex === 2) return [value];
  if (directive === "acl" && tokenIndex === 3) return [value];
  if (directive === "member" && tokenIndex === 1) return [value];
  if (directive === "member" && tokenIndex === 2) return [value, `role:${value}`];
  if (["user", "group", "scope", "service_account", "invitation", "api_key", "boundary"].includes(directive) && tokenIndex === 2) return [value];
  if (directive === "api_key" && tokenIndex === 3) return [value, `user:${value}`];
  if (directive === "invitation" && tokenIndex === 4) return roleListKeys(listItemAt(tokenInfo, character));
  return [];
}

function definitionKeysForBlockToken(blockDirective, field, tokenIndex, tokenInfo, character, valueToken = false) {
  if (!tokenInfo) return [];
  const value = cleanBlockValue(listItemAt(tokenInfo, character));
  if (!value || value === "[" || value === "]" || value === "{") return [];
  if (blockDirective === "members") {
    if (tokenIndex === 0) return [value];
    return roleListKeys(value);
  }
  if (tokenIndex === 0 && !valueToken) return [];
  if (field === "tenant") return [value];
  if (field === "parent" && blockDirective === "tenant") return [value];
  if (field === "parent" && blockDirective === "group") return [value, `group:${value}`];
  if (field === "parent" && blockDirective === "scope") return [value, `scope:${value}`];
  if (field === "inherits" || field === "roles") return roleListKeys(value);
  if (field === "subject") return [value];
  return [];
}

function definitionKeysForOption(directive, key, value) {
  if (!value) return [];
  if (key === "parent:" && directive === "tenant") return [value];
  if (key === "parent:" && directive === "group") return [value, `group:${value}`];
  if (key === "parent:" && directive === "scope") return [value, `scope:${value}`];
  if (key === "inherits:" || key === "roles:") return roleListKeys(value);
  if (key === "scopes:") return listKeys(value, "scope");
  if (key === "groups:") return listKeys(value, "group");
  if (key === "invited_by:") return [value, `user:${value}`];
  return [];
}

function optionPartsAt(tokenInfo, character) {
  const colon = tokenInfo.value.indexOf(":");
  if (colon <= 0) return undefined;
  const key = tokenInfo.value.slice(0, colon + 1);
  if (!optionsByDirectiveToken(key)) return undefined;
  const relative = Math.max(0, character - tokenInfo.start - key.length);
  const value = tokenInfo.value.slice(colon + 1);
  const parts = value.split(",");
  let offset = 0;
  for (const part of parts) {
    if (relative >= offset && relative <= offset + part.length) {
      return { key, value: part };
    }
    offset += part.length + 1;
  }
  return { key, value };
}

function listItemAt(tokenInfo, character) {
  const relative = Math.max(0, character - tokenInfo.start);
  const parts = tokenInfo.value.split(",");
  let offset = 0;
  for (const part of parts) {
    if (relative >= offset && relative <= offset + part.length) return part;
    offset += part.length + 1;
  }
  return tokenInfo.value;
}

function optionsByDirectiveToken(key) {
  return ["parent:", "priority:", "inherits:", "owner:", "expires:", "status:", "desc:", "client:", "roles:", "scopes:", "groups:", "invited_by:"].includes(key);
}

function roleListKeys(value) {
  return listKeys(value, "role");
}

function listKeys(value, prefix) {
  return value.split(",").filter(Boolean).flatMap((id) => [id, `${prefix}:${id}`]);
}

function isResourceLike(token) {
  return /^[A-Za-z_][\w-]*:.+/.test(token) && !/^(parent|priority|inherits|owner|expires|status|desc|client|roles|scopes|groups|invited_by):/.test(token);
}

function isSubjectLike(token) {
  return /^(user|group|service):.+$/.test(token) || token === "guest";
}

function isPermissionLike(token) {
  return /^[^:,\s]+:.+$/.test(token);
}

function unquote(value) {
  return value.replace(/^["'`]|["'`]$/g, "");
}

function diag(line, start, end, message, severity) {
  return new vscode.Diagnostic(new vscode.Range(line, start, line, end), message, severity);
}

function rangeDiag(document, lineNo, token, message, severity) {
  const text = document.lineAt(lineNo).text;
  const start = Math.max(0, text.indexOf(token));
  return diag(lineNo, start, start + token.length, message, severity);
}

function symbolKind(directive) {
  switch (directive) {
    case "tenant":
      return vscode.SymbolKind.Namespace;
    case "policy":
      return vscode.SymbolKind.Function;
    case "role":
      return vscode.SymbolKind.Class;
    case "acl":
      return vscode.SymbolKind.Key;
    case "user":
    case "service_account":
      return vscode.SymbolKind.Object;
    case "group":
      return vscode.SymbolKind.Module;
    case "scope":
      return vscode.SymbolKind.Interface;
    case "invitation":
      return vscode.SymbolKind.Event;
    case "api_key":
      return vscode.SymbolKind.Key;
    case "boundary":
      return vscode.SymbolKind.Enum;
    default:
      return vscode.SymbolKind.String;
  }
}

async function validateActiveFileWithCLI(output, diagnostics) {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "authz") {
    vscode.window.showWarningMessage("Open an AuthZ DSL file first.");
    return;
  }
  await validateFileWithCLI(editor.document, output, diagnostics, true);
}

async function validateFileWithCLI(document, output, diagnostics, showOutput = false) {
  const root = workspaceRoot(document);
  const file = document.uri.fsPath;
  if (!root || !fs.existsSync(path.join(root, "cmd", "authz-config", "main.go"))) {
    if (showOutput) vscode.window.showWarningMessage("AuthZ CLI not found in this workspace; using built-in diagnostics only.");
    return;
  }
  const result = await runAuthzConfig(root, ["validate", file]);
  output.appendLine(`$ go run ./cmd/authz-config validate ${file}`);
  output.appendLine(result.stdout);
  output.appendLine(result.stderr);
  const cliDiagnostics = diagnosticsFromCLI(document, result);
  diagnostics.set(document.uri, [...validateDocument(document), ...cliDiagnostics]);
  if (showOutput) {
    output.show(true);
    if (result.code === 0) vscode.window.showInformationMessage("AuthZ configuration is valid.");
    else vscode.window.showErrorMessage("AuthZ validation failed. See AuthZ DSL output.");
  }
}

async function formatActiveFileWithCLI(output) {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "authz") {
    vscode.window.showWarningMessage("Open an AuthZ DSL file first.");
    return;
  }
  const root = workspaceRoot(editor.document);
  const file = editor.document.uri.fsPath;
  if (!root || !fs.existsSync(path.join(root, "cmd", "authz-config", "main.go"))) {
    await vscode.commands.executeCommand("editor.action.formatDocument");
    return;
  }
  if (editor.document.isDirty) await editor.document.save();
  const result = await runAuthzConfig(root, ["fmt", file]);
  output.appendLine(`$ go run ./cmd/authz-config fmt ${file}`);
  output.appendLine(result.stderr);
  if (result.code !== 0) {
    output.appendLine(result.stdout);
    output.show(true);
    vscode.window.showErrorMessage("AuthZ format failed. See AuthZ DSL output.");
    return;
  }
  const fullRange = new vscode.Range(0, 0, editor.document.lineCount, editor.document.lineAt(editor.document.lineCount - 1).text.length);
  await editor.edit((edit) => edit.replace(fullRange, result.stdout.trimEnd() + "\n"));
  vscode.window.showInformationMessage("AuthZ file formatted with authz-config.");
}

async function previewPlan(output) {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "authz") {
    vscode.window.showWarningMessage("Open an AuthZ DSL file first.");
    return;
  }
  const root = workspaceRoot(editor.document);
  if (!root || !fs.existsSync(path.join(root, "cmd", "authz-config", "main.go"))) {
    vscode.window.showWarningMessage("AuthZ CLI not found in this workspace.");
    return;
  }
  if (editor.document.isDirty) await editor.document.save();
  const result = await runAuthzConfig(root, ["plan", editor.document.uri.fsPath, "--sync"]);
  output.appendLine(`$ go run ./cmd/authz-config plan ${editor.document.uri.fsPath} --sync`);
  output.appendLine(result.stdout);
  output.appendLine(result.stderr);
  const doc = await vscode.workspace.openTextDocument({ content: result.stdout || result.stderr, language: "plaintext" });
  await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
}

async function showPermissionGraph() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "authz") {
    vscode.window.showWarningMessage("Open an AuthZ DSL file first.");
    return;
  }
  const index = await buildWorkspaceIndex(editor.document);
  const graph = renderPermissionGraph(index);
  const doc = await vscode.workspace.openTextDocument({ content: graph, language: "markdown" });
  await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
}

async function explainActiveSymbol() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "authz") {
    vscode.window.showWarningMessage("Open an AuthZ DSL file first.");
    return;
  }
  const position = editor.selection.active;
  const index = await buildWorkspaceIndex(editor.document);
  const target = await referenceTarget(editor.document, position);
  const line = editor.document.lineAt(position.line).text;
  const parsed = parseLine(line);
  const tokenInfo = tokenAt(parsed, position.character);
  const id = target ? target.value : (tokenInfo ? tokenInfo.value : parsed.tokens[1] || "");
  const explanation = renderSymbolExplanation(index, id);
  const doc = await vscode.workspace.openTextDocument({ content: explanation, language: "markdown" });
  await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
}

function diagnosticsFromCLI(document, result) {
  if (result.code === 0) return [];
  const text = `${result.stdout}\n${result.stderr}`.trim();
  const lineMatch = /line\s+(\d+):\s*(.*)/i.exec(text);
  const line = lineMatch ? Math.max(0, Number(lineMatch[1]) - 1) : 0;
  const message = lineMatch ? lineMatch[2] : text || "authz-config validation failed";
  const maxLine = Math.max(0, Math.min(line, document.lineCount - 1));
  const length = document.lineAt(maxLine).text.length || 1;
  return [new vscode.Diagnostic(new vscode.Range(maxLine, 0, maxLine, length), message, vscode.DiagnosticSeverity.Error)];
}

function runAuthzConfig(root, args) {
  return new Promise((resolve) => {
    const child = cp.spawn("go", ["run", "./cmd/authz-config", ...args], { cwd: root, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => stdout += data.toString());
    child.stderr.on("data", (data) => stderr += data.toString());
    child.on("error", (err) => resolve({ code: 1, stdout, stderr: err.message }));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function renderPermissionGraph(index) {
  const lines = ["# AuthZ Permission Graph", ""];
  lines.push("## Tenants", ...index.tenants.map((id) => `- ${id}`), "");
  lines.push("## Subjects", ...index.subjects.map((id) => `- ${id}`), "");
  lines.push("## Roles", ...index.entries.filter((e) => e.directive === "role").map((e) => `- ${e.id}`), "");
  lines.push("## Policies", ...index.entries.filter((e) => e.directive === "policy").map((e) => `- ${e.id}`), "");
  lines.push("## ACLs", ...index.entries.filter((e) => e.directive === "acl").map((e) => `- ${e.id}`), "");
  lines.push("## Resources", ...index.resources.map((id) => `- ${id}`), "");
  lines.push("## Actions", ...index.actions.map((id) => `- ${id}`), "");
  return lines.join("\n");
}

function renderSymbolExplanation(index, id) {
  const lines = [`# AuthZ Symbol: ${id || "current symbol"}`, ""];
  const keys = [id, `role:${id}`, `user:${id}`, `group:${id}`, `scope:${id}`, `service:${id}`].filter(Boolean);
  const defs = keys.flatMap((key) => index.definitions.get(key) || []);
  const refs = index.references.filter((ref) => keys.includes(ref.key));
  if (defs.length) {
    lines.push("## Definitions");
    for (const loc of dedupeLocations(defs)) lines.push(`- ${path.basename(loc.uri.fsPath)}:${loc.range.start.line + 1}`);
    lines.push("");
  }
  if (refs.length) {
    lines.push("## References");
    for (const ref of dedupeReferenceRanges(refs)) lines.push(`- ${path.basename(ref.uri.fsPath)}:${ref.range.start.line + 1}`);
    lines.push("");
  }
  if (!defs.length && !refs.length) lines.push("No indexed definitions or references found.");
  return lines.join("\n");
}

function workspaceRoot(document) {
  const folder = document ? vscode.workspace.getWorkspaceFolder(document.uri) : vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  return folder ? folder.uri.fsPath : undefined;
}

function nearestDirective(value) {
  let best = "";
  let bestDistance = Infinity;
  for (const [directive] of directives) {
    const dist = levenshtein(value, directive);
    if (dist < bestDistance) {
      best = directive;
      bestDistance = dist;
    }
  }
  return bestDistance <= 3 ? best : "";
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function renderReferenceHtml() {
  const rows = directives.map(([name, syntax, description]) => `<tr><td><code>${name}</code></td><td><code>${syntax}</code></td><td>${description}</td></tr>`).join("");
  const optionRows = [...explanationRegistry.options.values()].map((doc) => `<tr><td><code>${doc.title}</code></td><td>${doc.summary}</td><td>${doc.example}</td></tr>`).join("");
  const fieldRows = [...explanationRegistry.fields.values()].map(([title, summary, example]) => `<tr><td><code>${title}</code></td><td>${summary}</td><td>${example}</td></tr>`).join("");
  const functionRows = [...explanationRegistry.functions.values()].map(([title, summary, example]) => `<tr><td><code>${title}</code></td><td>${summary}</td><td>${example}</td></tr>`).join("");
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
    h2 { margin-top: 28px; }
    table { border-collapse: collapse; width: 100%; }
    td, th { border-bottom: 1px solid var(--vscode-panel-border); padding: 8px; vertical-align: top; }
    code { color: var(--vscode-textPreformat-foreground); }
    .note { border-left: 3px solid var(--vscode-focusBorder); padding-left: 12px; margin: 12px 0; }
  </style>
</head>
<body>
  <h1>AuthZ DSL Syntax</h1>
  <div class="note">
    The engine evaluates explicit deny policies and ACLs before grants. Allows may come from policies, ACLs, RBAC roles, owner rules, or cross-tenant admin status.
  </div>
  <h2>Directives</h2>
  <table>
    <thead><tr><th>Directive</th><th>Syntax</th><th>Description</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <h2>How Evaluation Works</h2>
  <p>Policies match by tenant, action, resource pattern, effect, and ABAC condition. ACLs match explicit subjects/resources/actions. Roles grant RBAC permissions through <code>action:resource</code> entries and inherited roles. Deny matches override allow matches.</p>
  <h2>Tenant Hierarchy</h2>
  <p><code>parent:</code> records child-to-parent tenant, group, or scope relationships. For tenants, hierarchy can participate in ancestor/cross-tenant checks in the engine.</p>
  <pre><code>tenant org1 "Engineering Org" parent:root
tenant team1 "Backend Team" parent:org1</code></pre>
  <h2>Resource Patterns</h2>
  <p>Generic resources match runtime resources as <code>type:id</code>. <code>document:*</code> matches any document. <code>*</code> matches every resource. Route resources use <code>route:&lt;METHOD&gt;:&lt;path&gt;</code>.</p>
  <pre><code>document:*
route:GET:/users/*
route:*</code></pre>
  <h2>Role Permissions</h2>
  <p>Role permissions use <code>action:resource</code>. <code>*:project:*</code> means any action on project resources. <code>*:*</code> is full RBAC access and should be reserved for admin roles.</p>
  <pre><code>read:document:*
GET:route:GET:/admin/*
*:project:*</code></pre>
  <h2>ACL Subjects</h2>
  <p>ACL subjects can be concrete users, groups, service subjects, <code>guest</code>, or <code>*</code>. Group ACLs match subjects whose runtime groups include the group ID.</p>
  <pre><code>user:alice
group:engineering
guest</code></pre>
  <h2>Policy Conditions</h2>
  <p>Conditions are ABAC predicates over runtime subject, resource, action, and environment values.</p>
  <table>
    <thead><tr><th>Field</th><th>Meaning</th><th>Example</th></tr></thead>
    <tbody>${fieldRows}</tbody>
  </table>
  <h2>Condition Functions</h2>
  <table>
    <thead><tr><th>Function</th><th>Meaning</th><th>Example</th></tr></thead>
    <tbody>${functionRows}</tbody>
  </table>
  <h2>Options</h2>
  <table>
    <thead><tr><th>Option</th><th>Meaning</th><th>Example</th></tr></thead>
    <tbody>${optionRows}</tbody>
  </table>
</body>
</html>`;
}

module.exports = { activate, deactivate };
