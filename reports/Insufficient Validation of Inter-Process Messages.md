---
Title: Insufficient Validation of Inter-Process Messages
GeneratedBy: Electronegativity
Consequence: Medium
Likelihood: Possible
---

# Insufficient Validation of Inter-Process Messages

## Issue Description

Testing identified that inter-process communication (IPC) handlers in the vulnerable-app main process act on messages from the user interface without sufficient validation. The main process has full access to the operating system, so its handlers form the boundary between web content and the user’s computer.

- **Message sender not validated.** An inter-process communication (IPC) handler in the main process acts on messages without checking which page or frame sent them.
- **Message arguments not validated.** An inter-process communication (IPC) handler in the main process uses values received from the renderer in a sensitive operation, such as a file system, process or shell operation, without validating them.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:26` — channel `run`
  - Message sender not validated
  - Message arguments not validated
- `src/main.js:27` — channel `open`
  - Message sender not validated
  - Message arguments not validated

## Implication

- **Message sender not validated.** Any page able to send a message on the channel, including a page loaded from an unexpected origin or a frame within it, could trigger the handler’s privileged operation.
- **Message arguments not validated.** A page able to send the message could choose the value and make the handler read, modify or open files, or run programs, outside the intended scope of the operation.

*Note:* Exploitation requires an attacker to first run script in an application window, or to load their own content in one.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review lines 26 and 27:

  ```javascript
  24 |   });
  25 |
  26 |   ipcMain.handle('run', (event, command) => exec(command));
  27 |   ipcMain.on('open', (event, file) => shell.openPath(file));
  28 | });
  ```

  Line 26 shows that the handler for the `run` channel does not validate the sender of the message before acting on it, and passes values received from the user interface to start a process without validating them. Line 27 shows that the handler for the `open` channel does not validate the sender of the message before acting on it, and passes values received from the user interface to Electron’s `shell` module without validating them.

## Recommendations

- Validate the sender of every IPC message against the expected application origin before acting on it, and authorise the requested operation separately. Verify that a message sent from an unapproved page or frame is rejected.
- Validate the type and value of every argument at the handler, allow only the specific operations required, and resolve file paths within an approved directory. Verify that an out-of-scope value is rejected before the sensitive operation.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
function validateSender(frame) { return new URL(frame.url).origin === 'app://main'; }
ipcMain.handle('ch', (e, ...args) => { if (!validateSender(e.senderFrame)) return; /* … */ });
```

## References

- CWE-20: Improper Input Validation

  https://cwe.mitre.org/data/definitions/20.html

- Electron security checklist: 17. Validate the sender of all IPC messages

  https://www.electronjs.org/docs/latest/tutorial/security#17-validate-the-sender-of-all-ipc-messages
