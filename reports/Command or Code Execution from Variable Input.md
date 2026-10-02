---
Title: Command or Code Execution from Variable Input
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Unlikely
---

# Command or Code Execution from Variable Input

## Issue Description

Testing identified that vulnerable-app runs operating system commands, or evaluates code, built from variable input.

- **Operating system command built from variable input.** The application starts a process with a command that is built from a variable value, using a function that runs the command through the system shell.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:26` — Operating system command built from variable input

## Implication

- **Operating system command built from variable input.** An attacker able to influence the value could add shell syntax and run arbitrary commands with the privileges of the logged-in user.

*Note:* Exploitation requires an attacker to control the input that reaches the affected function.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review line 26:

  ```javascript
  24 |   });
  25 |
  26 |   ipcMain.handle('run', (event, command) => exec(command));
  27 |   ipcMain.on('open', (event, file) => shell.openPath(file));
  28 | });
  ```

  This shows that `exec()` runs a command built from data received from an IPC message from a renderer.

## Recommendations

- Run a fixed program with a separate, validated argument list (for example `execFile()` rather than `exec()`) so that input is never interpreted by a shell. Verify that input containing shell syntax is treated as data.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
execFile('converter', ['--input', validatedPath]);   // not exec(`converter ${name}`)
```

## References

- CWE-78: Improper Neutralization of Special Elements used in an OS Command

  https://cwe.mitre.org/data/definitions/78.html

- Node.js documentation: child processexeccommand options callback

  https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback

- Electron security checklist

  https://www.electronjs.org/docs/latest/tutorial/security
