# Electronegativity findings (redacted for sharing)

> Electronegativity findings, redacted for sharing: app, company and user names (and --redact terms), user folders, hosts (pseudonyms), query strings, e-mail and IP addresses and secret-like values are replaced; code is left out. Review this file before sending it.

**Reading this report (for a reviewer or an AI agent).** It was made from a scan of an Electron application whose identity has been removed on purpose: names appear as `<redacted>`, web hosts as `host-xxxxxxxx` (the same host always has the same alias), and addresses, folders and secrets as `<email>`, `<ip>`, `<user>`, `<uuid>` or `<redacted>`. Do not try to work out who the application or its owner is. Findings are ordered by severity; "Potential input source" is a check-level threat model, not a proven exploit. Useful replies: which findings to fix first and why, likely false positives, and how to confirm or fix each one.

- Tool 2.0.0; Electron 38.2.0; static scan only
- 9 findings: 1 high, 5 medium, 3 informational
- Potential source of input (based on check type): Raises impact 3, Shared content 2, Local access 2, Information 1, Network 1

## Findings, most severe first

### LIMIT_NAVIGATION_GLOBAL_CHECK (1 high)

Potential input source: Shared content. Possible interaction: A click on a crafted link. These are check-level threat models, not verified exploit conditions.

1. **HIGH/CERTAIN** `application-wide`: Missing navigation limits: no will-navigate handler and no setWindowOpenHandler

### CSP_GLOBAL_CHECK (1 medium)

Potential input source: Raises impact. Possible interaction: None of its own: it decides how far content that is already injected gets. These are check-level threat models, not verified exploit conditions.

1. **MEDIUM/CERTAIN** `application-wide`: No CSP has been detected in the target application

### PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK (1 medium)

Potential input source: Shared content. Possible interaction: Viewing the content is enough when it runs as script; a click when it is a link. These are check-level threat models, not verified exploit conditions.

1. **MEDIUM/CERTAIN** `application-wide`: Missing PermissionRequestHandler to limit specific permissions (e.g. openExternal) in response to events from particular origins.

### DEVTOOLS_JS_CHECK (1 medium)

Potential input source: Local access. Possible interaction: Access to the user's device or account. These are check-level threat models, not verified exploit conditions.

1. **MEDIUM/CERTAIN** `main.js:2`: DevTools are opened programmatically; ensure this cannot happen in production builds (always opened, including in production builds)

### IPC_SENDER_VALIDATION_JS_CHECK (1 medium)

Potential input source: Raises impact. Possible interaction: None of its own: it decides how far content that is already injected gets. These are check-level threat models, not verified exploit conditions.

1. **MEDIUM/FIRM** `main.js:1` (needs review): IPC handler does not appear to validate the sender (event.senderFrame) before acting on the message
   - details: `{"channel":"a"}`

### FUSES_GLOBAL_CHECK (1 medium)

Potential input source: Local access. Possible interaction: Access to the user's device or account. These are check-level threat models, not verified exploit conditions.

1. **MEDIUM/TENTATIVE** `application-wide` (needs review): No Electron Fuses configuration found. RunAsNode, NODE_OPTIONS, --inspect and ASAR integrity fuses are insecure by default

## Inventory (informational)

### IPC_HANDLER_JS_CHECK (1 informational)

Potential input source: Raises impact. Possible interaction: None of its own: it decides how far content that is already injected gets. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `main.js:1`: IPC handler: 'a'
   - details: `{"channel":"a","capabilities":[],"validatesArguments":false,"argumentsUsed":false}`

## Other informational findings

### ELECTRON_VERSION_JSON_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `package.json:1` (needs review): Gets the electron version used by inspecting the package.json file.

### CERTIFICATE_PINNING_GLOBAL_CHECK (1 informational)

Potential input source: Network. Possible interaction: None: an attacker on the network path acts while the app talks to its servers. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/FIRM** `application-wide` (needs review): No certificate pinning found (session.setCertificateVerifyProc); consider pinning the certificates of the backends the application trusts
