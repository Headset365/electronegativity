# Known gaps

Features that were planned but not added, and known limits of what was built. Each item can be picked up separately.

## Not added

These were started and rolled back. They need a separate approach (manual testing, a dedicated web application security assessment, or other tooling).

### 1. Planted test content in watch mode

- **What it would do:** a second test account posts harmless marked content into shared parts of the app, and watch mode reports whether it comes back as live HTML when another user views it in the desktop app.
- **Why it matters:** this is the stored-content threat model (content from one user rendered by another user's client), the root cause of most published Electron vulnerabilities.
- **Covered today by:** manual testing. The "Renderer attack surface" table in the HTML report shows how much an injection in each window could reach.

### 2. HTML injection analysis for AngularJS and rich-text editors

- **What it would do:**
  - treat data from the server (`$http`, `fetch`, axios, WebSocket and `message` events) as untrusted;
  - check AngularJS HTML trust and template compilation (`$sce.trustAs*`, `$compile`/`$interpolate`/`$eval` of server data, `ng-bind-html-unsafe`);
  - recognize rich-text editor HTML-loading APIs (`execCommand('insertHTML')`, TinyMCE, CKEditor, Quill, Froala, Summernote);
  - recognize HTML strings passed to `$()` / `angular.element()`;
  - raise server-fed HTML sinks to HIGH when the window has Node.js access.
- **Covered today by:** `XSS_SINK_JS_CHECK` covers the standard DOM sinks: `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()` and building strings for `.append()` and similar, and React `dangerouslySetInnerHTML`. `ANGULAR_SCE_DISABLED_JS_CHECK` covers `$sce` being switched off globally.
- **Related finding from manual testing:** the document editor's HTML is filtered on the client but less strictly on the server. Server-side sanitization with an allowlist-based sanitizer should be verified independently of this tool.

## Limits of what was built

### 3. Watch mode only observes the main process

- **What's missing:** it records windows, page loads, headers, IPC, `shell` calls, permissions and certificate errors, but not what happens inside pages (DOM changes, script behavior).
- **Possible approach:** a renderer-side observer injected through the Chrome DevTools Protocol.

### 4. Coverage is measured by IPC channels only

- **What's missing:** the report lists registered IPC channels the session never used, but not screens, routes or windows that were never opened.
- **Possible approach:** compare the windows and routes found by the static scan with the pages observed at runtime.

### 5. Preload scripts are missing from the runtime table

- **What's missing:** Electron's `getLastWebPreferences()` doesn't report the preload path, so the "Observed while the app ran" table has no preload column. The static table shows preloads where they can be resolved.
- **Possible approach:** record `webPreferences.preload` when windows are constructed (wrap the `BrowserWindow` constructor in the hook).

### 6. Fuses are read from build configuration only

- **What's missing:** `FUSES_*` checks read `@electron/fuses` calls and packager configuration. They don't read the fuse wire in the packaged executable, so changes made by the build pipeline aren't seen.
- **Possible approach:** read the fuse sentinel from the packaged binary (the format `@electron/fuses` reads).

### 7. Static and runtime findings are not merged

- **What's missing:** a problem seen both in the code and at runtime appears twice, for example `NODE_INTEGRATION_JS_CHECK` and `RUNTIME_NODE_INTEGRATION`.
- **Possible approach:** link runtime windows to the static window findings (by preload script and loaded URL/file) and show one finding with both sources.

### 8. Permission check handlers are not observed

- **What's missing:** watch mode records permission requests and their answers (`setPermissionRequestHandler`), but not `setPermissionCheckHandler`, which answers synchronous permission queries.
- **Possible approach:** wrap `setPermissionCheckHandler` in the hook the same way as the request handler.
