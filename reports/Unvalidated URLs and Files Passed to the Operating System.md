---
Title: Unvalidated URLs and Files Passed to the Operating System
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Unlikely
---

# Unvalidated URLs and Files Passed to the Operating System

## Issue Description

Testing identified that vulnerable-app passes URLs or file paths to the operating system to open without sufficient validation.

- **Unvalidated URLs opened by the operating system.** The application passes a URL to the operating system to open, using `shell.openExternal()`, without restricting which schemes and destinations are allowed.
- **Non-web protocols not blocked.** The URLs passed to the operating system are not restricted to web protocols, so `file:` URLs and custom application protocols are also opened.
- **Network share locations not blocked.** The URLs and paths passed to the operating system are not checked for network-share locations, such as UNC (`\\server\share`) or `file://server/` paths.
- **Unvalidated file paths opened by the operating system.** The application passes a file path to the operating system to open or reveal, without validating the path.
- **Executable files not blocked.** The paths the application asks the operating system to open are not restricted by file type, so executables, scripts and shortcuts are also opened.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:22`
  - Unvalidated URLs opened by the operating system
  - Non-web protocols not blocked
  - Network share locations not blocked
- `src/main.js:27`
  - Unvalidated file paths opened by the operating system
  - Executable files not blocked

## Implication

- **Unvalidated URLs opened by the operating system.** A link or value controlled by an attacker could make the operating system open an arbitrary destination or launch the handler for another protocol on the user’s computer.
- **Non-web protocols not blocked.** An attacker-controlled link could launch another application registered for a custom protocol, or open a local file, which on some systems can lead to running a program.
- **Network share locations not blocked.** Opening an attacker-chosen network share can make Windows send the user’s credentials to the attacker’s server, where they could be captured and cracked or relayed.
- **Unvalidated file paths opened by the operating system.** If the path can be influenced by a page, document or message, the user could be presented with, or made to open, a file other than the one intended.
- **Executable files not blocked.** If an attacker can choose the path, opening an executable file would run it with the privileges of the logged-in user.

*Note:* Exploitation requires an attacker to control the URL or path passed to the operating system, for example through a link in content shown by the application, and in most cases a user to click it.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review lines 22 and 27:

  ```javascript
  20 |   win.webContents.on('will-navigate', (event, url) => console.log('navigating to', url));
  21 |   win.webContents.setWindowOpenHandler(({ url }) => {
  22 |     shell.openExternal(url);
  23 |     return { action: 'allow' };
  24 |   });
  25 |
  26 |   ipcMain.handle('run', (event, command) => exec(command));
  27 |   ipcMain.on('open', (event, file) => shell.openPath(file));
  28 | });
  ```

  Line 22 shows that the value passed to `shell.openExternal()` comes from a window.open() call or link in web content and is not validated. Line 27 shows that the value passed to `shell.openPath()` comes from an IPC message from a renderer and is not validated.

## Recommendations

- Parse every URL before passing it to the operating system and allow only approved schemes, normally `https:`, and approved destinations. Verify that links using other schemes or destinations are rejected.
- Reject every scheme other than `https:` (and `mailto:` where required) before passing a URL to the operating system. Verify that `file:` and custom protocol links are rejected.
- Block UNC paths and `file:` URLs that refer to remote hosts before any hand-off to the operating system. Verify with a harmless test location that such paths are rejected.
- Resolve each path to its final location, allow only paths within an approved directory and reject path traversal. Verify that a path outside the approved directory never reaches the operating system.
- Reject executable file types (such as `.exe`, `.bat`, `.cmd`, `.ps1`, `.js`, `.lnk`, `.msi` and `.scr`) in document-opening workflows, and require an explicit user action to launch a program. Verify the restriction with a harmless test file.

The following illustrative examples show the recommended approach. They should be adapted to the application’s own code:

```javascript
const u = new URL(url); if (u.protocol === 'https:' && allowedHosts.has(u.hostname)) shell.openExternal(u.href);
```

```javascript
const full = path.resolve(base, name); if (!full.startsWith(base + path.sep) || /\.(exe|bat|cmd|ps1|js|lnk|msi|scr)$/i.test(full)) return;
```

## References

- CWE-73: External Control of File Name or Path

  https://cwe.mitre.org/data/definitions/73.html

- Electron security checklist: 15. Do not use shellopenexternal with untrusted content

  https://www.electronjs.org/docs/latest/tutorial/security#15-do-not-use-shellopenexternal-with-untrusted-content

- Electron API documentation: Shell

  https://www.electronjs.org/docs/latest/api/shell#shellopenpathpath
