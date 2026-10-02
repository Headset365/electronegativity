---
Title: Browser Security Controls Disabled
GeneratedBy: Electronegativity
Consequence: Medium
Likelihood: Likely
---

# Browser Security Controls Disabled

## Issue Description

Testing identified that vulnerable-app disables or weakens security protections built into the Chromium browser engine on which Electron applications are based.

- **Browser security protections disabled.** A browser security protection, such as the same-origin policy or the blocking of insecure content, is disabled for an application window or for the whole application.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:10` — Browser security protections disabled

## Implication

- **Browser security protections disabled.** Content loaded in the affected window could read data from other origins or load scripts over unencrypted connections, which the browser would otherwise prevent.

*Note:* The impact depends on the content loaded in the affected windows. The settings themselves were confirmed in the application’s configuration.

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

  This shows that web security, which enforces the same-origin policy, is disabled for the window.

## Recommendations

- Re-enable the affected protection and remove security-disabling command-line switches. Where the application needs to exchange data across origins, allow it through narrowly scoped server-side policy, and verify the packaged window enforces the default protections.

## References

- CWE-693: Protection Mechanism Failure

  https://cwe.mitre.org/data/definitions/693.html

- Electron security checklist: 6. Do not disable websecurity

  https://www.electronjs.org/docs/latest/tutorial/security#6-do-not-disable-websecurity
