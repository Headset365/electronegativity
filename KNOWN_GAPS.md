# Known gaps

The features that were previously planned but not built have now been added. This file records what each one does and
the limits that remain, so the boundaries of the analysis stay clear.

## Now implemented

### 1. Planted test content in watch mode

- **What it does:** `--watch-marker <token>` tells the observer which token to look for. Put content carrying the token
  into a shared part of the app from one account, then open it as another user. The renderer-side observer reports
  `RUNTIME_MARKER` and says whether the token came back as live HTML (HIGH: stored input reaches another view
  unneutralized) or was shown safely (informational).
- **Why it matters:** this is the stored-content threat model (content from one user rendered by another user's client),
  the root cause of most published Electron vulnerabilities.
- **Remaining limit:** detection is a heuristic. The token counts as live HTML when it became part of the markup
  structure (a tag or attribute name) or ended up in an event-handler attribute. The token in visible text or in an
  ordinary attribute value (a form field's value, a title) is how safely displayed content looks, and is reported as
  shown safely.

### 2. HTML injection analysis for AngularJS and rich-text editors

- **What it does:**
  - treats data from the server (`fetch`, `$http`, axios and the bodies they resolve to, and `message`/WebSocket events)
    as untrusted, and raises server-fed HTML sinks to HIGH (`XSS_SINK_JS_CHECK`). Inside a server callback, only values
    derived from the response or message count as server-fed;
  - checks AngularJS HTML trust and template compilation — `$sce.trustAsHtml`, `$sce.trustAs(HTML, …)`, `$compile`,
    `$interpolate`, `$parse` of dynamic data (`ANGULAR_TRUST_HTML_JS_CHECK`; `$compile` only for markup strings, not the
    `$compile(element.contents())` directive idiom), and `ng-bind-html-unsafe` in templates
    (`ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK`);
  - recognizes rich-text editor HTML-loading APIs — TinyMCE, CKEditor, Quill, Froala, Summernote
    (`RICH_TEXT_EDITOR_JS_CHECK`) and `execCommand('insertHTML')`;
  - recognizes HTML strings passed to `$()` / `angular.element()` (`XSS_SINK_JS_CHECK`).
- **Also covered:** `XSS_SINK_JS_CHECK` continues to cover the standard DOM sinks (`innerHTML`/`outerHTML`,
  `insertAdjacentHTML`, `document.write`, jQuery `.html()`/`.append()` and React `dangerouslySetInnerHTML`), and
  `ANGULAR_SCE_DISABLED_JS_CHECK` covers `$sce` being switched off globally.
- **Remaining limit:** server-side sanitization still has to be verified independently; static analysis sees only the
  client. Generic editor method names (`setData`, `setContent`, `insertContent`) are only matched on editor-like
  receivers (`editor`, `tinymce`, `CKEDITOR`, `quill`, ...), so an editor held in a variable with an unrelated name is
  missed.

### 3. Renderer-side observer in watch mode

- **What it does:** a small read-only script is installed in each page and polled from the main process. It reports DOM
  changes that carry script — inserted inline event-handler attributes (`onerror=`, …) and `javascript:` URLs
  (`RUNTIME_DOM_INJECTION`) — and the planted-marker reflections above. This is watch mode observing what happens inside
  pages, not only the main process.
- **Remaining limit:** the observer is injected with `executeJavaScript` and polled (world- and CSP-agnostic), rather
  than through the Chrome DevTools Protocol, so it reports the security-relevant script-bearing insertions and marker
  reflections rather than every DOM mutation. Plain `<script>` insertions are recorded but not reported (too common in
  normal apps).

### 4. Coverage beyond IPC channels

- **What it does:** in addition to the registered IPC channels that were never used (`RUNTIME_COVERAGE`), the report now
  lists windows the static scan found that were never opened during the session (`RUNTIME_WINDOW_COVERAGE`), by comparing
  the windows found statically with the pages observed at runtime.
- **Remaining limit:** windows are matched by their preload file name (resolved statically from constants,
  `path.join`/`path.resolve` and template strings), so a window with no preload cannot be told apart from another, and
  windows sharing a preload count as observed together; in-page routes inside a single window are not enumerated.

### 5. Preload scripts in the runtime table

- **What it does:** `getLastWebPreferences()` does not report the preload path, so the hook captures it where each window
  is constructed (the `BrowserWindow`/`BrowserView`/`WebContentsView` constructors are wrapped through a Proxy of the
  electron module). The "Observed while the app ran" table now has a preload column.
- **Remaining limit:** an ES-module app that imports the window constructors before the hook runs keeps its original
  binding, so its preloads may not be captured.

### 6. Fuses read from the packaged binary

- **What it does:** the `FUSES_*` checks read `@electron/fuses` calls and packager configuration; watch mode of a
  packaged app additionally reads the fuse wire embedded in the shipped executable (`PACKAGED_FUSES`), so states set by
  the build pipeline — and not by code the scan can see — are caught.
- **Remaining limit:** reads the V1 fuse wire format; the binary is scanned for the fuse sentinel, which is present in
  standard Electron builds. On macOS the wire is read from `Contents/Frameworks/Electron Framework.framework`, as
  `@electron/fuses` does; when no wire is found, watch mode says so. Verified against `@electron/fuses` on Electron 38.

### 7. Static and runtime findings are reconciled

- **What it does:** runtime windows are linked to the static window findings by preload script (the report shows where
  each observed window was defined, and which static windows were observed at runtime), and a problem seen both in the
  code and at runtime — for example `NODE_INTEGRATION_JS_CHECK` and `RUNTIME_NODE_INTEGRATION` — is marked as confirmed
  by the other source instead of standing alone.
- **Remaining limit:** the confirmation link is drawn at the level of the finding type; it does not yet map each runtime
  window one-to-one onto the exact static window it came from beyond the preload match.

### 8. Permission check handlers are observed

- **What it does:** watch mode records synchronous permission checks (`setPermissionCheckHandler`) the same way as
  permission requests, reporting what the app's handler — or Electron's default, when the app sets none — allows
  (`RUNTIME_PERMISSION_CHECK`). Checks Chromium makes without a page origin (e.g. media device enumeration) are ignored.
