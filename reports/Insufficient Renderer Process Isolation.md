---
Title: Insufficient Renderer Process Isolation
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Likely
---

# Insufficient Renderer Process Isolation

## Issue Description

Testing identified that one or more windows in vulnerable-app run web content with reduced isolation from the operating system and from the application’s privileged code.

- **Node.js integration enabled.** Node.js integration is enabled for an application window, which gives any script running in that window direct access to Node.js and, through it, to the operating system.
- **Context isolation or sandbox disabled.** Context isolation or the renderer sandbox is disabled for an application window, which removes the separation between page script, the preload script and the operating system.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:10`
  - Node.js integration enabled
  - Context isolation or sandbox disabled
- vulnerable-app (application-wide) — Node.js integration enabled

## Implication

- **Node.js integration enabled.** If an attacker can run script in the window, for example through cross-site scripting or a compromised remote resource, they could read and modify local files, run programs and access application data with the privileges of the logged-in user.
- **Context isolation or sandbox disabled.** Script running in the page could tamper with the preload script’s objects and reach the privileged functions it holds, and a compromise of the renderer process would not be contained by the sandbox.

*Note:* The impact described requires an attacker to first run script in an affected window, for example through a separate cross-site scripting flaw or a compromised remote resource.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review line 10:

  ```javascript
   8 | app.whenReady().then(() => {
   9 |   const win = new BrowserWindow({
  10 |     webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false, webviewTag: true, preload: path.join(__dirname, 'preload.js') }
  11 |   });
  12 |   win.loadURL('http://example.com');
  ```

  This shows that Node.js integration is enabled for the window, that context isolation is disabled for the window, that the renderer sandbox is not enabled for the window, and that a preload script runs in a window without context isolation, so page script shares its environment.

- Review the configuration of vulnerable-app, which shows that Node.js integration is enabled while resources are loaded over unencrypted HTTP.

## Recommendations

- Disable Node.js integration for every window that renders web content, and expose only the operations the interface needs through a narrowly scoped preload script. Verify in the packaged application that page script can no longer access `require` or `process`.
- Enable context isolation and the renderer sandbox for every window. Verify in the packaged application that the preload functions still work and that page script cannot access the preload script’s objects.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
webPreferences: { sandbox: true }
```

## References

- CWE-653: Improper Isolation or Compartmentalization

  https://cwe.mitre.org/data/definitions/653.html

- Electron security checklist: 2. Do not enable Node.js integration for remote content

  https://www.electronjs.org/docs/latest/tutorial/security#2-do-not-enable-nodejs-integration-for-remote-content

- Electron security checklist: 3. Enable context isolation

  https://www.electronjs.org/docs/latest/tutorial/security#3-enable-context-isolation

- Electron security checklist: 4. Enable process sandboxing

  https://www.electronjs.org/docs/latest/tutorial/security#4-enable-process-sandboxing

- Electron security checklist: 20. Do not expose Electron APIs to untrusted web content

  https://www.electronjs.org/docs/latest/tutorial/security#20-do-not-expose-electron-apis-to-untrusted-web-content
