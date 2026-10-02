---
Title: Privileged Functionality Exposed to Web Content
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Likely
---

# Privileged Functionality Exposed to Web Content

## Issue Description

Testing identified that vulnerable-app exposes privileged functionality, or a shared session, to web content that should not have access to it.

- **Privileged functionality exposed by the preload script.** The preload script exposes privileged functionality to page script, such as the whole inter-process communication (IPC) interface rather than a small set of specific functions.

## Affected

The following locations in vulnerable-app are affected:

- `src/preload.js:2` — Privileged functionality exposed by the preload script

## Implication

- **Privileged functionality exposed by the preload script.** Any script running in the page, including injected script, could use the exposed functionality to invoke privileged operations in the main process with the authority of the application.

*Note:* Exploitation requires script controlled by an attacker to run in a page that has access to the exposed functionality.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/preload.js` and review line 2:

  ```javascript
  1 | const { contextBridge, ipcRenderer } = require('electron');
  2 | contextBridge.exposeInMainWorld('ipc', ipcRenderer);
  3 | window.render = (html) => { document.body.innerHTML = html; };
  ```

  This shows that the preload script exposes `ipcRenderer` to page script through the context bridge.

## Recommendations

- Expose only a small, specific set of functions through the context bridge, each passing validated arguments to a dedicated handler, and never expose Electron or Node.js objects directly. Verify that page script cannot reach any other privileged functionality.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
contextBridge.exposeInMainWorld('api', { openDocument: (id) => ipcRenderer.invoke('document:open', String(id)) });
```

## References

- CWE-749: Exposed Dangerous Method or Function

  https://cwe.mitre.org/data/definitions/749.html

- Electron security checklist: 20. Do not expose Electron APIs to untrusted web content

  https://www.electronjs.org/docs/latest/tutorial/security#20-do-not-expose-electron-apis-to-untrusted-web-content
