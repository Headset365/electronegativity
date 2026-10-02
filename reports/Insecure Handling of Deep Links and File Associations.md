---
Title: Insecure Handling of Deep Links and File Associations
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Unlikely
---

# Insecure Handling of Deep Links and File Associations

## Issue Description

Testing identified that vulnerable-app acts on input received through deep links, custom protocols or file associations without sufficient validation. This input can come from any web page, email or file a user opens.

- **Unvalidated deep link or file association input.** The application registers a custom protocol or file association, and acts on the parameters it receives from outside the application without validating them.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:18` — Unvalidated deep link or file association input

## Implication

- **Unvalidated deep link or file association input.** A crafted link on a web page or in an email, or a crafted file, could make the application perform an unintended action or open a file of the attacker’s choosing.

*Note:* Exploitation requires a user to open a crafted link or file, for example from a web page or an email.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review line 18:

  ```javascript
  16 | session.defaultSession.setCertificateVerifyProc((request, callback) => callback(0));
  17 |
  18 | protocol.handle('app', (request) => net.fetch('file://' + path.join(__dirname, new URL(request.url).pathname)));
  19 |
  20 | win.webContents.on('will-navigate', (event, url) => console.log('navigating to', url));
  ```

  This shows that a custom protocol handler serves files using a path taken from the request, without checking that the path stays within the intended folder.

## Recommendations

- Parse deep link and file association input against a fixed format, allow only documented actions and resolve file paths within approved locations. Verify that unknown actions and out-of-scope paths are rejected.

## References

- CWE-20: Improper Input Validation

  https://cwe.mitre.org/data/definitions/20.html

- Electron security checklist: 18. Avoid usage of the file protocol and prefer usage of custom protocols

  https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols
