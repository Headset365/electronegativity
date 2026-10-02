---
Title: Debugging Features Enabled in Production
GeneratedBy: Electronegativity
Consequence: Low
Likelihood: Unlikely
---

# Debugging Features Enabled in Production

## Issue Description

Testing identified that the production build of vulnerable-app retains development or debugging features.

- **Developer tools or test functions available.** The production build retains developer functionality, such as code that opens the Chromium developer tools or test-only functions.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:13` — Developer tools or test functions available

## Implication

- **Developer tools or test functions available.** A user, or someone with access to the device, could use these functions to inspect and modify the application’s behaviour and data, or bypass controls enforced in the user interface.

*Note:* These features are generally available only to someone already using the application on the device.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review line 13:

  ```javascript
  11 | });
  12 | win.loadURL('http://example.com');
  13 | win.webContents.openDevTools();
  14 |
  15 | session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => callback(true));
  ```

  This shows that the application opens the developer tools in every build, including production builds.

## Recommendations

- Disable developer tools and remove test-only functionality from production builds, for example by setting `devTools: !app.isPackaged`. Verify that the developer tools cannot be opened in the released application.

The following illustrative example shows the recommended approach. It should be adapted to the application’s own code:

```javascript
webPreferences: { devTools: !app.isPackaged }
```

## References

- CWE-489: Active Debug Code

  https://cwe.mitre.org/data/definitions/489.html

- Electron API documentation: Web contents

  https://www.electronjs.org/docs/latest/api/web-contents#contentsopendevtoolsoptions
