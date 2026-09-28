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

### 9. Validation assistant

- **What it does:** with a marker, watch mode tells the tester during the session what to do to confirm or rule out the
  findings that need review (send a request again with the marker in named fields, paste formatted content, click the
  marker link, attach the marker file), and records where the marker goes: HTML sinks (with the script line, mapped
  through captured source maps), request fields, `openExternal`, `openPath`, navigations, new windows, IPC and command
  lines. Static findings are marked confirmed, seen or ruled out at runtime.
- **Remaining limit:** only the marker's path is followed. A sink reached only by code that ran before the observer was
  installed in a page (before `dom-ready`) isn't recorded; `openExternal`, `openPath`, navigation and command-line
  evidence is tied to the kind of finding, not to one call site; and the IPC sender check itself still has to be read in
  the handler.

### 10. Sending the marker request automatically

- **What it does:** when the validation assistant spots a save request that carries HTML (for example
  `PUT /api/matters/{id}/documents`), it shows exactly what it proposes to send — the HTML fields and the marker value it
  would put there (`<span data-ENG…="1">ENG…</span>`) and the target endpoint — and asks `y/N` (the default is no, so an
  Enter meant for the next prompt never sends). On yes, it re-sends the request the app already made, with the marker put
  into those fields, through that request's own session (so a logged-in test account's cookies apply), and reports the
  status. The re-sent request is observed like any other, so the marker's onward path (rendering, HTML sinks) is picked
  up as usual. On no, or when it can't send, it falls back to naming the endpoint and fields for the tester to send by
  hand or replay from a proxy. If several save requests arrive at once it asks about them one at a time; a question left
  open when the app closes is cancelled (counted as no) so it can't be answered by accident at the next prompt.
- **Why it matters:** it closes the loop the assistant used to leave to the tester — planting the stored content — so
  confirming stored-content injection needs one keypress instead of switching to the app or a proxy to resend.
- **How it stays faithful:** the re-send reuses the request's own headers (`Authorization`, `User-Agent`, custom client
  ids and the like), so header-token auth works, not only session cookies; the body is rebuilt without going through
  `JSON.parse`, so a large integer id keeps its exact digits and numbers aren't reformatted; and a request is only kept
  in memory for re-sending while the command channel is open, so an ordinary watch run holds none of it.
- **Remaining limit:** the marker is put only into the fields that carried markup, so a plain-text save is left for the
  tester (naming a title, an id or a status would overwrite unrelated data); only JSON and urlencoded bodies are rebuilt
  (a multipart upload is left for the tester); it needs an interactive terminal (`--watch` or `--app`, not `--watch-log`
  replay) and Electron 25+ (`session.fetch`); and it is offered once per endpoint. Only the harmless marker is ever put
  into the body — nothing else is sent, the kept headers and body stay in memory, and no request content is written to
  the log or the diagnostics report.

## Remaining gaps

- **The server.** Static and runtime analysis see the client. Watch mode lists the API endpoints pages called and those
  that accepted HTML (`RUNTIME_HTML_ENDPOINT`), as starting points, but whether the server sanitizes stored content has
  to be tested against the server itself (for example with an intercepting proxy and a second account).
- **Sanitizer bypasses.** The configuration of DOMPurify, AngularJS `$sanitize` and the rich-text editors is checked,
  and `--watch-marker` shows whether planted content comes back as live HTML, but the tool does not try to get markup
  past a sanitizer.
- **Links built from data in React.** `href={value}` with a `javascript:` URL (Grafana's CVE-2020-11110) is not
  reported: every dynamic link in a React app would be, and AngularJS links go through `$compileProvider`, whose
  allowlists are checked.
- **Remote code that needs a login to download.** `--remote` sends the headers given with `--remote-header` to the site;
  watch mode downloads with the app's own session. Templates or chunks guessed from the code are fetched without the
  session after a watch session unless `--remote-header` is given.
- **Minified code without source maps.** Scanned as is; the data-flow checks follow it less well than original sources.

## Requested, not implemented

- **A combined report across a guided run's sessions.** Requested: one report bringing together the static scan and
  every watch session. Not built yet; each session still has its own report. Being handled outside this tool.

Built since it was requested here: sending the marker request automatically (see
["Sending the marker request automatically"](#10-sending-the-marker-request-automatically) above).
