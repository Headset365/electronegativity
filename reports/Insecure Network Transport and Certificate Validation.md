---
Title: Insecure Network Transport and Certificate Validation
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Likely
---

# Insecure Network Transport and Certificate Validation

## Issue Description

Testing identified that vulnerable-app communicates over unencrypted connections or does not properly validate server certificates.

- **Unencrypted connections.** The application loads content or communicates over unencrypted HTTP or WebSocket connections.
- **Certificate validation disabled.** Certificate validation is disabled or overridden, so the application accepts invalid TLS certificates.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js` — 4 locations (lines 6, 12, 16, 30)
  - Certificate validation disabled
  - Unencrypted connections
- `src/index.html:1` — Unencrypted connections
- `package.json:4` — Certificate validation disabled

## Implication

- **Unencrypted connections.** An attacker on the same network, or anywhere on the network path, could read or modify the traffic, including injecting script into content the application loads.
- **Certificate validation disabled.** An attacker on the network path could impersonate the application’s servers with their own certificate, and read or modify traffic that should be protected, including credentials.

*Note:* Exploitation requires an attacker to be positioned on the network path between the application and its servers.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review lines 12 and 16:

  ```javascript
  10 |   webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false, webviewTag: true, preload: path.join(__dirname, 'preload.js') }
  11 | });
  12 | win.loadURL('http://example.com');
  13 | win.webContents.openDevTools();
  14 |
  15 | session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => callback(true));
  16 | session.defaultSession.setCertificateVerifyProc((request, callback) => callback(0));
  17 |
  18 | protocol.handle('app', (request) => net.fetch('file://' + path.join(__dirname, new URL(request.url).pathname)));
  ```

  Line 12 shows that content is loaded over unencrypted HTTP. Line 16 shows that the certificate verification handler accepts every certificate, which disables certificate validation.

- Open `src/main.js` and review line 6:

  ```javascript
  4 | const path = require('path');
  5 |
  6 | app.commandLine.appendSwitch('ignore-certificate-errors');
  7 |
  8 | app.whenReady().then(() => {
  ```

  This shows that the `--ignore-certificate-errors` command-line switch is applied, which disables certificate validation for the whole application.

- Open `src/main.js` and review line 30:

  ```javascript
  28 | });
  29 |
  30 | app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  31 |   event.preventDefault();
  32 |   callback(true);
  ```

  This shows that the `certificate-error` handler accepts every invalid certificate.

- Open `src/index.html` and review line 1:

  ```html
  1 | <html><body><script src="http://cdn.example.com/app.js"></script><webview src="https://example.com" allowpopups></webview></body></html>
  ```

  This shows that a resource is loaded over unencrypted HTTP (\<script\> http://cdn.example.com/app.js).

- Open `package.json` and review line 4:

  ```json
  2 | "name": "vulnerable-app",
  3 | "main": "src/main.js",
  4 | "scripts": { "start": "NODE_TLS_REJECT_UNAUTHORIZED=0 electron ." },
  5 | "devDependencies": { "electron": "11.5.0" },
  6 | "build": { "appId": "com.example.vulnerable" }
  ```

  This shows that certificate validation for Node.js connections is disabled in the `start` npm script. This applies only when the application is started from source with that script, typically during development, and not to the packaged application.

## Recommendations

- Use HTTPS and secure WebSocket (WSS) connections for all communication. Verify that no request, redirect or resource uses an unencrypted connection.
- Remove the code and settings that accept invalid certificates, and rely on the operating system’s certificate validation. Verify that a connection presenting an invalid test certificate is rejected.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
app.on('certificate-error', (event, wc, url, error, cert, callback) => { callback(false); });
```

## References

- CWE-319: Cleartext Transmission of Sensitive Information

  https://cwe.mitre.org/data/definitions/319.html

- Electron security checklist: 1. Only load secure content

  https://www.electronjs.org/docs/latest/tutorial/security#1-only-load-secure-content

- Electron API documentation: Session

  https://www.electronjs.org/docs/latest/api/session#sessetcertificateverifyprocproc

- Electron API documentation: Command line switches

  https://www.electronjs.org/docs/latest/api/command-line-switches

- Electron API documentation: App (‘certificate-error’ event)

  https://www.electronjs.org/docs/latest/api/app#event-certificate-error

- Node.js documentation: NODE_TLS_REJECT_UNAUTHORIZED environment variable

  https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue
