---
Title: Insufficient Navigation and New Window Restrictions
GeneratedBy: Electronegativity
Consequence: High
Likelihood: Possible
---

# Insufficient Navigation and New Window Restrictions

## Issue Description

Testing identified that windows in vulnerable-app are not sufficiently restricted from navigating to, or opening, content outside the application.

- **Navigation and redirects not restricted.** Application windows are not prevented from navigating, or following a server redirect, to destinations outside the application.
- **New windows not restricted.** Page content can open new windows, through scripted popups, links or middle-clicks, without restriction.
- **Embedded content not restricted.** The application allows embedded content, through `<webview>` tags or iframes, without restricting its source and privileges.

## Affected

The following locations in vulnerable-app are affected:

- `src/main.js:20` — Navigation and redirects not restricted
- vulnerable-app (application-wide) — Navigation and redirects not restricted
- `src/main.js:10` — Embedded content not restricted
- `src/main.js:23` — New windows not restricted
- `src/index.html:1` — New windows not restricted

## Implication

- **Navigation and redirects not restricted.** A link or redirect could load an external page in an application window, where it would inherit the window’s preload script, session and other privileges.
- **New windows not restricted.** A crafted link could open an external page in a new application window with privileges it should not have, or pass an unsafe destination to the operating system.
- **Embedded content not restricted.** Less trusted embedded content could gain privileges, such as Node.js access or the parent window’s preload script, that should be limited to the application’s own pages.

*Note:* The impact depends on the privileges of the affected windows, and is greatest where they have Node.js integration or a privileged preload script.

## Reproduction and Evidence

The issue can be reproduced as follows:

- Obtain the source code of vulnerable-app. The file paths below are relative to its root folder.

- Open `src/main.js` and review lines 20 and 23:

  ```javascript
  18 | protocol.handle('app', (request) => net.fetch('file://' + path.join(__dirname, new URL(request.url).pathname)));
  19 |
  20 | win.webContents.on('will-navigate', (event, url) => console.log('navigating to', url));
  21 | win.webContents.setWindowOpenHandler(({ url }) => {
  22 |   shell.openExternal(url);
  23 |   return { action: 'allow' };
  24 | });
  ```

  Line 20 shows that the `will-navigate` handler never blocks a navigation, so windows can navigate to any destination. Line 23 shows that the `setWindowOpenHandler()` handler allows every URL to open a new window.

- Review the configuration of vulnerable-app, which shows that no `will-navigate` handler restricts where windows can navigate.

- Open `src/main.js` and review line 10. This shows that the `<webview>` tag is enabled without a `will-attach-webview` handler to check embedded content before it is created, and is enabled.

- Open `src/index.html` and review line 1:

  ```html
  1 | <html><body><script src="http://cdn.example.com/app.js"></script><webview src="https://example.com" allowpopups></webview></body></html>
  ```

  This shows that a `<webview>` tag allows popups.

## Recommendations

- Block navigation to unapproved destinations in `will-navigate` and `will-redirect` handlers, allowing only the application’s own origins. Verify that links and redirects to an external origin are blocked.
- Deny new windows by default in `setWindowOpenHandler()`, and open approved external links in the system browser after validating their scheme and destination. Verify ordinary clicks, middle-clicks and scripted popups.
- Avoid `<webview>` where possible. Otherwise, validate the source and settings of each embedded view before it is created (`will-attach-webview`) and apply the `sandbox` attribute to iframes. Verify the settings in effect at runtime.

The following illustrative examples show the recommended approach. They should be adapted to the application’s own code:

```javascript
win.webContents.on('will-navigate', (e, url) => { if (new URL(url).origin !== ownOrigin) e.preventDefault(); });
```

```javascript
win.webContents.setWindowOpenHandler(({ url }) => { if (isAllowed(url)) shell.openExternal(url); return { action: 'deny' }; });
```

## References

- CWE-601: URL Redirection to Untrusted Site

  https://cwe.mitre.org/data/definitions/601.html

- Electron security checklist: 13. Disable or limit navigation

  https://www.electronjs.org/docs/latest/tutorial/security#13-disable-or-limit-navigation

- Electron security checklist: 14. Disable or limit creation of new windows

  https://www.electronjs.org/docs/latest/tutorial/security#14-disable-or-limit-creation-of-new-windows

- Electron security checklist: 11. Do not use allowpopups for webviews

  https://www.electronjs.org/docs/latest/tutorial/security#11-do-not-use-allowpopups-for-webviews

- Electron security checklist: 12. Verify webview options before creation

  https://www.electronjs.org/docs/latest/tutorial/security#12-verify-webview-options-before-creation
