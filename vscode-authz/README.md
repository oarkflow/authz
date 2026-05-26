# AuthZ DSL VS Code Extension

Syntax highlighting, snippets, hovers, diagnostics, formatting, and IntelliSense for `.authz` and `.dsl` files.

## Features

- TextMate syntax highlighting for directives, options, engine keys, condition fields, condition functions, actions, resources, effects, statuses, comments, and strings.
- Snippets for every supported directive, including block-form policies, roles, ACLs, members, tenants, and engine config.
- IntelliSense for directives, directive-specific options, actions, resources, effects, statuses, engine keys, condition fields, condition operators, and condition helpers.
- Same-file completions for tenant, role, user, group, and scope IDs in both inline and block syntax.
- Hovers for directives and condition functions.
- Lightweight diagnostics for unknown directives/options, bad effects, malformed role permissions, duplicate IDs, empty list items, invalid expiration timestamps, and unterminated quotes.
- Basic document formatting that trims trailing whitespace and normalizes inline comment spacing.
- A standalone stdio LSP server at `src/server.js` for `.authz`/`.dsl` completion, hover details, diagnostics, definitions, references, document symbols, and formatting.

## Run Locally

1. Open this folder in VS Code:

   ```bash
   code vscode-authz
   ```

2. Press `F5` to launch an Extension Development Host.
3. Open `examples/config.authz` from this repository in the new VS Code window.

The extension is dependency-free at runtime and uses plain JavaScript, so it does not need a compile step.

## Language Server

The bundled server speaks standard LSP JSON-RPC over stdio:

```bash
pnpm run lsp
```

It keeps an in-memory workspace index for tenants, roles, users, groups, scopes, service accounts, policies, ACLs, boundaries, actions, resources, and subject references. Built-in diagnostics are always available; set `AUTHZ_LSP_CLI=1` to additionally call `go run ./cmd/authz-config validate` when a matching authz workspace is open.

## Syntax Reference

Run `AuthZ DSL: Show Syntax Reference` from the command palette for an in-editor quick reference.

Block syntax is supported:

```authz
policy allow-admin {
  tenant org1
  effect allow
  actions [read write delete]
  resources [document:*]
  when {
    subject.roles contains any [admin, superadmin]
  }
  priority 100
}
```
