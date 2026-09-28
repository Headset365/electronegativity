# Electronegativity findings (redacted for sharing)

> Electronegativity findings, redacted for sharing: app, company and user names (and --redact terms), user folders, hosts (pseudonyms), query strings, e-mail and IP addresses and secret-like values are replaced; code is left out. Review this file before sending it.

**Reading this report (for a reviewer or an AI agent).** It was made from a scan of an Electron application whose identity has been removed on purpose: names appear as `<redacted>`, web hosts as `host-xxxxxxxx` (the same host always has the same alias), and addresses, folders and secrets as `<email>`, `<ip>`, `<user>`, `<uuid>` or `<redacted>`. Do not try to work out who the application or its owner is. Findings are ordered by severity; "Potential input source" is a check-level threat model, not a proven exploit. Useful replies: which findings to fix first and why, likely false positives, and how to confirm or fix each one.

- Tool 2.0.0; Electron 38.2.0; static scan only
- 11 findings: 4 low, 7 informational
- Potential source of input (based on check type): Information 5, Shared content 4, Raises impact 1, Network 1

## Findings, most severe first

### PERMISSION_REQUEST_HANDLER_JS_CHECK (2 low)

Potential input source: Shared content. Possible interaction: Viewing the content is enough when it runs as script; a click when it is a link. These are check-level threat models, not verified exploit conditions.

1. **LOW/FIRM** `src/main/index.mjs:32` (needs review): Permission handler: setPermissionRequestHandler grants some permissions after checking the requesting origin; review the allowlist
2. **LOW/FIRM** `src/main/index.mjs:35` (needs review): Permission handler: setPermissionCheckHandler grants some permissions after checking the requesting origin; review the allowlist

### OPEN_EXTERNAL_JS_CHECK (1 low)

Potential input source: Shared content. Possible interaction: A click on a crafted link. These are check-level threat models, not verified exploit conditions.

1. **LOW/FIRM** `src/main/index.mjs:20` (needs review): Review the use of openExternal (the value is validated first; review the allowlist)

### PROTOCOL_HANDLER_JS_CHECK (1 low)

Potential input source: Shared content. Possible interaction: Opening a crafted deep link. These are check-level threat models, not verified exploit conditions.

1. **LOW/FIRM** `src/main/index.mjs:25` (needs review): Review the use of custom protocol handlers (the handler serves files and checks paths; review the containment check)

## Inventory (informational)

### EXPOSED_API_JS_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `src/preload/index.mts:4`: API exposed to web content: window.app (getVersion, onUpdateAvailable); uses ipc (get-version, update-available)
   - details: `{"capabilities":{"getVersion":["ipc"],"onUpdateAvailable":["ipc"]},"world":"app","members":["getVersion","onUpdateAvailable"],"channels":["get-version","update-available"]}`

### IPC_HANDLER_JS_CHECK (1 informational)

Potential input source: Raises impact. Possible interaction: None of its own: it decides how far content that is already injected gets. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `src/main/index.mjs:40`: IPC handler: 'get-version'
   - details: `{"channel":"get-version","capabilities":[],"validatesArguments":true,"argumentsUsed":false}`

### WINDOW_SUMMARY_JS_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `src/main/index.mjs:46`: Window security settings: BrowserWindow (nodeIntegration off (default), contextIsolation on (default), sandbox on (default), webSecurity on (default), preload index.mjs)
   - details: `{"partition":"default","settings":{"nodeIntegration":{"value":false,"source":"default"},"contextIsolation":{"value":true,"source":"default"},"sandbox":{"value":true,"source":"default"},"webSecurity":{"value":true,"source":"default"},"nodeIntegrationInSubFrames":{"value":false,"source":"default"},"webviewTag":{"value":false,"source":"default"},"allowRunningInsecureContent":{"value":false,"source":"default"}},"preload":"index.mjs","window":"BrowserWindow"}`

### IPC_CHANNEL_MAP_GLOBAL_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/FIRM** `src/main/index.mjs:40`: IPC channel: 'get-version' handled at index.mjs:40, sent from index.mts
   - details: `{"channel":"get-version","senders":["/home/<user>/electronegativity/test/apps/<redacted>/src/preload/index.mts"],"windows":[],"passThrough":[]}`

## Other informational findings

### ELECTRON_VERSION_JSON_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `package.json:1` (needs review): Gets the electron version used by inspecting the package.json file.

### PRELOAD_JS_CHECK (1 informational)

Potential input source: Information. Possible interaction: Not applicable. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/CERTAIN** `src/main/index.mjs:49` (needs review): Preload script with context isolation; what it exposes through contextBridge is analyzed by CONTEXT_BRIDGE_EXPOSURE_JS_CHECK

### CERTIFICATE_PINNING_GLOBAL_CHECK (1 informational)

Potential input source: Network. Possible interaction: None: an attacker on the network path acts while the app talks to its servers. These are check-level threat models, not verified exploit conditions.

1. **INFORMATIONAL/FIRM** `application-wide` (needs review): No certificate pinning found (session.setCertificateVerifyProc); consider pinning the certificates of the backends the application trusts
