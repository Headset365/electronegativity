---
Title: Permissive Browser Permission Handling
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Possible
---

# Permissive Browser Permission Handling

## Issue Description

Testing identified that vulnerable-app grants browser permissions to web content without checking which page is asking or which permission is requested.

- **Permission requests granted without restriction.** The application grants browser permission requests, such as camera, microphone, location or notifications, without checking which page is asking or which permission is requested.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:15` — Permission requests granted without restriction

## Implication

- **Permission requests granted without restriction.** Any page loaded in the application, including injected or external content, could obtain these capabilities without the user being asked.

*Note:* Exploitation requires content controlled by an attacker to be loaded in an application window.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review line 15:

  ```javascript
  13 | win.webContents.openDevTools();
  14 |
  15 | session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => callback(true));
  16 | session.defaultSession.setCertificateVerifyProc((request, callback) => callback(0));
  ```

  This shows that the permission request handler grants every permission to every origin.

## Recommendations

- Handle permission requests with `setPermissionRequestHandler()`, granting only the specific permissions the application needs to its own origins and denying all others. Verify that a request from an unapproved origin is denied.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
ses.setPermissionRequestHandler((wc, permission, cb, details) => cb(permission === 'notifications' && new URL(details.requestingUrl).origin === ownOrigin));
ses.setPermissionCheckHandler((wc, permission, origin) => permission === 'notifications' && origin === ownOrigin);
```

## References

- CWE-862: Missing Authorisation

  https://cwe.mitre.org/data/definitions/862.html

- Electron security checklist: 5. Handle session permission requests from remote content

  https://www.electronjs.org/docs/latest/tutorial/security#5-handle-session-permission-requests-from-remote-content
