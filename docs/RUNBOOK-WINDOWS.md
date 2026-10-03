# Running Electronegativity on a Windows host against a packaged app (.exe)

Run everything against a **test environment** with **test accounts**, never production. All commands are PowerShell.

## 1. Install

1. Install Node.js **24 LTS** (x64 `.msi`) from <https://nodejs.org/>, with the defaults. Git is not needed.
2. Open a **new** PowerShell window (so the new `PATH` applies) and check the version: it must be 24.11 or later (or 22.18+).

   ```powershell
   node -v
   ```

3. Install the tool from GitHub (no administrator rights needed; it installs for your user):

   ```powershell
   npm install -g https://github.com/Headset365/electronegativity/archive/refs/heads/merged-electron-dynamic.tar.gz
   electronegativity -h | findstr debug-launch   # prints a line: this branch is installed
   ```

   To update later, run the same `npm install -g` command again.

   If PowerShell refuses to run `electronegativity` ("running scripts is disabled"), use `electronegativity.cmd` instead, or
   run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

4. Network (only if it applies to this host):

   ```powershell
   # outbound traffic goes through a proxy (needed for the advisory lookups and --remote)
   $env:HTTPS_PROXY = "http://proxy.example:8080"; $env:NODE_USE_ENV_PROXY = "1"
   # the test server's HTTPS certificate comes from an internal CA (needed for --remote only)
   $env:NODE_EXTRA_CA_CERTS = "C:\certs\internal-ca.pem"
   ```

   With no internet access at all, add `--offline` to every command below (the Electron end-of-life and advisory checks
   are then skipped).

## 2. Before you start

- Watch mode loads its observer into the installed app through the Node inspector (started on a local port for the
  session only). Builds with the `EnableNodeCliInspectArguments` fuse off can't be observed: the tool checks this before
  starting and says so (the static scan works on any build). If that happens, use a test build with the fuse on.
- Close the app completely, including any tray icon: a second copy usually hands over to the running one and exits.

  ```powershell
  Get-Process MyApp -ErrorAction SilentlyContinue | Stop-Process
  ```

## 3. Run it

Point the tool at where the app is installed. It finds the executable and the app's code itself (install folder, the
`.exe`, Squirrel's `app-<version>` folders, or the folder above the install folder such as `C:\Program Files\<Company>`):

```powershell
cd C:\
electronegativity --app "C:\Program Files\MyApp" --redact "CompanyName,internal.host.name"
```

`--redact` is optional: the app's name, your user name, the machine name and your home folder are always removed from the
diagnostics files; list any other words to remove (company name, internal host names).

What happens:

1. It prints what it found and the results folder (`C:\electronegativity-<UTC date and time>`, e.g. `C:\electronegativity-2026-09-30T08-52-43Z`), then scans all of the app's
   code, including screens behind the login.
2. It prints a **marker** for this run (e.g. `ENGK7Q2XM`) and asks: **Start watch session 1?** Press Enter. The app
   opens. As **account A**:
   - log in, then open every main screen, menu, dialog and settings page;
   - in the editor: create a document containing the marker (e.g. `Test ENGK7Q2XM`), paste formatted content from Word,
     drag and drop text and a file, import a `.docx`, use any file picker or "open" dialog;
   - share the document with account B (or put it where other users see it: comments, notes, previews);
   - try a `myapp://` link or a file association if the app has them;
   - close the app completely (File > Exit or the tray's Quit).
   While the app runs, the terminal shows `[validate]` lines: follow them. They ask you to send a request again with the
   marker in named fields, to paste formatted content (open the `<marker>-paste-me.html` file from the results folder in
   a browser, select all, copy, paste into the editor), to click the marker link `https://example.invalid/<marker>`
   placed in a document, or to attach the `<marker>.txt` file. They also say what the marker showed (✓ shown safely or
   blocked, ✗ confirmed). A summary is printed when the app closes.
3. **Optional, tests the server:** before the next session, in Burp, take account A's request that saves a document and
   put this harmless markup in the body: `<span data-ENGK7Q2XM="1">ENGK7Q2XM</span>` (with your marker). The endpoint is
   in `steps\session-1-report.html` under "API endpoint called", flagged "contains HTML".
4. It asks: **Start watch session 2?** Press Enter. As **account B**: log in, open everything that shows account A's
   content (the document, previews, search results, notifications, comments, exports or print preview), then close the
   app completely.
5. Press `s` when asked about session 3 to finish. The results folder then holds:
   - `report.html` and `report.json`: **one report of the whole run**, the static findings with what each session
     validated (marked with the session that showed it) and what the sessions found;
   - `reports\`: the client findings, one Markdown file per finding, ready for the client report (Australian English,
     reproduction steps and recommendations as bullets, the app named after its `.exe`), and `components.xlsx`, the
     components workbook the "Outdated Software Components" finding refers to (its links are checked; any that couldn't
     be are named in its "Links to validate manually" column);
   - `testerNotes\`: for each finding, your working notes: how it was rated, every instance with its recorded evidence
     (including those left out of the client finding), how to check each one by hand, and what the sessions covered.
     Each ends with a **Before release** checklist (mask secrets, review tentative instances, check the rating...) whose
     items link to `How to Prepare Findings for Release.md` in the same folder, a step-by-step guide to each check.
     Findings whose evidence can show a secret also say so in their `Notes`. They are not for the client;
   - `diagnostics.json`, with a section per step;
   - `steps\`: each step's own reports (`static-report.html`, `session-1-report.html`, ...), kept as backups.

In the report, use the **Validation** filter: "Seen at runtime" lists the findings the marker reached (with the
script line for HTML sinks), "Confirmed at runtime" the ones the captured traffic proved (requests over plain http, an
intercepting proxy's certificate accepted), and "Needs review, not validated" what is left, each with how to check it.

In `report.html`, `RUNTIME_MARKER` LOW (with `live` in its details) means the marker came back as live markup (stored
content reaches another user's view unneutralized, script execution not proven); INFORMATIONAL means it was shown safely
as text. Don't filter the report to HIGH only: this finding would be hidden.

The code the app's pages loaded from the server is downloaded during each session with your logged-in session and
scanned too: findings in it point at the URL it came from. A captured file identical to one in the package (an app
that serves its own pages through `protocol.handle('https')` or an `app://` scheme) is scanned once, as the package file;
the console says how many.

### What to look at in the results

- **Electron end of life and advisories** are raised even when only the `.exe` names the Electron version (packaged apps
  rarely have it in `package.json`): "Outdated Software Components" then includes Electron, its advisories and the
  Chromium fixes it misses.
- **RPC routers** (electron-trpc and similar) answer on one IPC channel. Each procedure behind it that writes or deletes
  files, opens paths, starts processes, changes the proxy or returns decrypted secrets is listed on its own
  (`IPC_RPC_PROCEDURE_JS_CHECK`, e.g. `osIntegrationRouter.deleteFile`), under "Insufficient Validation of
  Inter-Process Messages".
- **HTML built from strings**: a template literal with tags and unescaped `${…}` values (titles, tags, names) is
  reported (`HTML_TEMPLATE_JS_CHECK`) when the markup goes somewhere HTML is parsed or built: an HTML sink or jQuery
  insertion, a variable or property named for markup (or, in minified code, a variable that collects several pieces
  of markup), a function that renders, or a whole document. The app's own translation tables are not counted as values, as are the sinks such HTML usually ends in: `iframe.srcdoc`, `srcDoc` in compiled
  React, `contentDocument.write` and `createContextualFragment`. Iframes created in compiled code without `sandbox` are
  reported too, HIGH when the frame shows generated HTML in a window with `nodeIntegration` and no context isolation.
  To check one, put the marker in the listed value (a note title, a tag), then use the feature that builds the HTML:
  export, print or preview.
- **Frames seen during a session** (`RUNTIME_IFRAME`): every frame a page showed, its origin, its sandbox and any
  external script inside it. A frame in the app's own origin without an effective sandbox is reported.
- **Navigation allowlists** that compare host names only (no scheme check) are reported MEDIUM: `http://` on the allowed
  host gets through.
- **`--prove` navigation and new-window results**: "the app opened no window of its own, but its handler passed the URL
  to the operating system" means the in-app window was denied and the URL went to `shell.openExternal()`. That is not
  "blocked"; check the scheme handling.
- **Updates**: the feed check uses the address the app sets in code (`setFeedURL`) before `app-update.yml`. A missing
  `publisherName` is reported even when the `.exe` is signed: electron-updater then checks no installer signature. If
  the app downloads an update during a session, a note says so (later sessions may run a newer version). Turn off
  automatic updates in the test environment where the app allows it.
- **Cleartext addresses handed to Electron APIs** (spell-check dictionaries, `downloadURL`, `net.request`) are reported
  with the API and address.
- **Components workbook**: React sub-packages (`react-is`, `scheduler`) are named as themselves, not as React. pdf.js is
  listed, with a note when the app turns off `isEvalSupported` (CVE-2024-4367 mitigated). A library found only in code
  loaded from the app's server is marked `loaded-from-server`: the fix is a server deployment, not the installer.

- **Web code shipped next to the app** (`resources\stage`, `resources\appearance`: pages the app serves from its own
  local server) is scanned as part of the package, and shown as `resources/<folder>/...`.
- **Compiled React and Vue HTML**: `dangerouslySetInnerHTML` in bundles (`jsx("div", {dangerouslySetInnerHTML: …})`,
  including through a wrapper such as `getHtml(message)`) and Vue's `innerHTML` prop are HTML sinks.
- **Authentication switched off in one mode** (`isElectron ? [] : [checkToken]`, `isElectron ? next() : auth(...)`) is
  reported with the routes it protects, under "Local Services Accessible Without Adequate Access Control".
- **Local services** (`--prove`): every TCP port an app process listens on gets a read-only probe of `/` (GET and a CORS
  preflight with a foreign web origin and a `chrome-extension://` origin, no credentials). A service that lets those
  origins read its answers, or listens on every interface, is reported (`RUNTIME_LOCAL_SERVICE`).
- **Launcher scripts** shipped next to the `.exe` (`.bat`, `.cmd`, `.ps1`, `.sh`) are read for
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, `--ignore-certificate-errors`, `--disable-web-security`, `--no-sandbox`, debugging
  ports and `ELECTRON_RUN_AS_NODE`.
- **Campaigns**: requests replayed by the tool no longer carry the headers Chromium refuses (Origin, Referer, `Sec-*`),
  which made every case fail; a campaign that delivered nothing says so, and restores nothing. Saves whose route reads
  (`getConf`, `lsNotebooks`) or deletes (`removeNotebook`) are not offered, and record IDs (`rootID`, `notebook`,
  `dataType`) are not offered as content fields. Also put the HTML form of the marker in metadata: titles, names, tags or
  labels, table captions, database or column names, icons, and a value the app rejects, as the assistant now suggests.
- **After a session**, the app's own local server (127.0.0.1) is not crawled again: it stopped with the app.

- **TypeScript and Babel builds**: calls compiled as `(0, module_1.fn)(…)` are read as `module_1.fn(…)`, so checks see
  `exec`, `writeFile` and `shell.openPath` in compiled CommonJS code too.
- **SQL built from values** (`` `SELECT … WHERE FileID = ${fileID}` ``) is reported, HIGH when the value comes from an
  IPC message, under "SQL Injection in Local Database Queries".
- **Programs started from the working directory** (`ADODB.PATH = './resources/adodb.js'`, `spawn('./bin/tool.exe')`).
- **A page choosing the app's destinations**: an IPC handler that stores what a page sends (`setLoginModel(model)`) in
  state that later decides which address windows load, or where requests carrying the token go.
- **Write, then open**: an IPC handler that writes a file at a page-chosen path and then opens it with
  `shell.openPath` is HIGH.
- **Allowlists in helpers** (`if (!isAllowedUrl(url)) event.preventDefault()`) are read: the hosts, host-name-only
  comparisons and subdomain wildcards are reported. A `setWindowOpenHandler` that allows windows without
  `overrideBrowserWindowOptions` needs review. Preload inheritance is not assumed: the proof records handler options
  separately from effective options of a naturally created child window.

Less noise than before: timers given a callback are not code evaluation; paste, drop, file-picker, FileReader and
`message` handlers are their own check (`RENDERER_INPUT_JS_CHECK`, not "Deep Links") and are informational unless the
input reaches an operation; template credentials (`username:password@…`), routes, selectors and constant names are not
secrets; signed download links (S3, Azure SAS, GitHub release assets) and JSON query values are not "secret in URL"; the
tool's own debugging port is left out and UDP endpoints are summarised once; a signature Windows could not finish
checking (`Unknown`) is informational, to verify on a connected workstation; translated text, grammar tokens
(`variable-2`), protocol method names and regular expressions are not secrets; product licence keys shipped as JWTs and
Firebase web API keys are informational (public by design); default permission checks are one finding per origin; and a
window moving from the app's boot page to its own local server is not reported as navigation away; a shortcut to the
app itself with fixed arguments, and a `second-instance` handler that only looks for a fixed switch, are informational.

## 4. Useful variations

```powershell
# point at the .exe directly, or choose the results folder
electronegativity --app "$env:LOCALAPPDATA\MyApp\app-2.4.1\MyApp.exe" --out C:\eng-results

# static scan only (no sessions), or two sessions without being asked
electronegativity --app "C:\Program Files\MyApp" --sessions 0
electronegativity --app "C:\Program Files\MyApp" --sessions 2

# the app needs command-line arguments, or shows a blank window on a VM
electronegativity --app "C:\Program Files\MyApp" --watch-args "--disable-gpu"

# also fetch templates and screens the sessions never opened, from the test servers only (nothing from any other host),
# logged in with the same Cookie and Authorization the app sent them during the session (log in, use the app, close it
# without logging out: the download runs right after)
electronegativity --app "C:\Program Files\MyApp" --remote app.example.com,api.example.com --remote-header Authorization,Cookie

# or set a header by hand, e.g. account A's cookie from Burp (typed at a prompt, which keeps it out of the PowerShell history)
$Cookie = Read-Host "Cookie (name=value)"
electronegativity --app "C:\Program Files\MyApp" --remote https://test-server.example/ --remote-header "Cookie: $Cookie"

# the Electron version couldn't be detected (the output says "Couldn't detect Electron version")
electronegativity --app "C:\Program Files\MyApp" -e 38.2.0

# only HIGH and MEDIUM findings with firm or certain confidence in the reports
electronegativity --app "C:\Program Files\MyApp" -s medium -c firm

# re-analyze a session without running the app again (the log path is printed at the end of each session)
electronegativity --watch-log "$env:TEMP\electronegativity-watch-XXXXXX\session.jsonl" -i "C:\Program Files\MyApp" -r -o session-1b.html
```

The individual options still work on their own: `-i "C:\Program Files\MyApp" -o static.html` for a static scan, and
`--watch "C:\Program Files\MyApp" -o session.html` for one watch session. Every run also writes the client findings and
the components workbook to a `reports` folder, and the tester notes to a `testerNotes` folder next to it: in the run's
report folder, next to the first `-o` file, or in the folder you ran it from, with `report.json` next to them: the data
the findings were written from.

### Bounded proofs (`--prove`) and `proof.json`

`--prove` turns several "review this" items into recorded results during a watch session. These tests need no
configuration:

- the app's navigation and new-window handlers, asked about a test URL (nothing navigates or opens);
- the app's permission handlers, asked whether a foreign origin may use the camera (no camera is opened);
- a self-signed HTTPS request through the app's sessions (does the app accept an invalid certificate?);
- the packaged `.exe` started in Node mode with a harmless expression (the RunAsNode fuse);
- the update feed (metadata only: nothing is downloaded or installed), when the app sets an exact `latest.yml` or
  `RELEASES` address while you use it, or ships one in `resources\app-update.yml` (electron-builder's generic, GitHub,
  S3 and Spaces providers; a private repository, a token or another provider needs the address in the profile).

Start with those, without a profile:

```powershell
electronegativity --app "C:\Program Files\MyApp" --prove --sessions 1
```

A profile (`proof.json`) adds the tests that need to know something about this app. Make one only after that first run,
from what its report shows:

1. Copy the template next to your results and open it:

   ```powershell
   Copy-Item "$(npm root -g)\@doyensec\electronegativity\docs\proof.example.json" C:\eng\proof.json
   notepad C:\eng\proof.json
   ```

   It holds four sections; a section left empty (or out) keeps its default:

   ```json
   { "origins": ["https://eng-proof.invalid"], "feeds": [], "links": [], "services": [] }
   ```

2. **`origins`** (optional): the "foreign site" the handlers are asked about. 1 to 8 exact origins, scheme and host
   (and port) only, no path or trailing slash: `"https://eng-proof.invalid"`. It is never contacted. Keep the default
   unless you want another name in the evidence.
3. **`feeds`** (optional): the update metadata to inspect, only if the first run's update-feed result was skipped
   (the tool already reads `resources\app-update.yml` when it can). Find the address in Burp, as a request ending in
   `latest.yml` or `RELEASES`, or ask the client for it. Up to 8 exact addresses, no credentials or tokens in them:
   `"https://updates.example.com/win/latest.yml"`.
4. **`links`** (only after reviewing the code): a function the app's own page exposes that opens one URL, to see whether
   non-web links (`file:`, unknown protocols) are filtered before they reach Windows. Find it in the preload script
   (`contextBridge.exposeInMainWorld`) of the extracted `app.asar`, and read what it does: it must only open the link.

   ```json
   { "reviewed": true, "page": "https://app.example.com/", "method": "appLinks.open" }
   ```

   `page` is the start of the address of a page where that function exists; `method` its dotted name. The hand-off to
   Windows is blocked by the tool.
5. **`services`** (only after reviewing the route): a port the app's own process listens on (the first run's report
   lists them, or `Get-NetTCPConnection -State Listen -OwningProcess (Get-Process MyApp).Id` while it runs) and a
   **read-only** route on it, to see whether it answers without credentials or to a foreign origin.

   ```json
   { "reviewed": true, "port": 8123, "path": "/status", "transport": "http", "requiresAuth": true }
   ```

   `transport` is `"http"` or `"websocket"`; `requiresAuth` is what the app's design says should be true (it is
   recorded as your expectation). Never list a route that changes anything.
6. `"reviewed": true` is your statement that you read that function or route and that calling it in a disposable test
   session has no other effect. Entries without it are refused. At most 8 entries per section; the file must be valid
   JSON (double quotes, no trailing commas, no comments). A mistake stops the run before the app starts, naming the
   section.
7. Run again with the profile:

   ```powershell
   electronegativity --app "C:\Program Files\MyApp" --prove --proof-profile C:\eng\proof.json --sessions 1
   ```

Each result says what it establishes and what it does not; errors and timeouts are listed as coverage limits, not as
safe. `docs\PROOF-WATCH-WINDOWS.md` in the installed package (`$(npm root -g)\@doyensec\electronegativity`) has the details, including the separate `--ipc-profile`
and `--logout-check` opt-ins (run `--logout-check` in its own session, without `--auto-campaign`).

### Updating the findings of an earlier scan to new templates

After a finding template changes (a revised fuse finding, say), the findings of an earlier scan can be written again
from that scan's `report.json`, without scanning again:

```powershell
electronegativity --rerender "C:\eng-results\report.json"
```

The new findings go to `reports\newReports\`, with a new `components.xlsx`, and their tester notes to
`reports\newTesterNotes\`. The links of the new workbook are checked again (add `--offline` to skip that); its column
"Changes since the earlier workbook" says, for each component, which links are now found or no longer found, and
`newReports-review.md` lists the components whose links changed. All their content comes from the scan's data; the earlier findings are only read and left as
they are. `reports\newReports-review.md` lists what was changed by hand in the earlier findings (a rating, an edited,
added or removed section), quoting the earlier text so you can carry it over. A finding since renamed (such as "Renderer
Isolation Weakened", now "Insufficient Renderer Process Isolation") is compared with its new file. For findings written
before this version, the tool can't tell a template change from a manual edit: the review then lists every part that
differs, for you to check. Use `--old-reports <folder>` if the earlier findings are not in the `reports` folder next to
`report.json` (an older scan may have them in a `markdown` folder, which is found by itself).

## 5. What to send back

Only `diagnostics.json`. Open it first and check it contains nothing identifying: the app name, user name,
machine name, home folder and the `--redact` words are replaced, and hosts are pseudonymized. Keep the `.html` reports
yourself: they contain code locations and URLs.

## 6. Clean up

```powershell
Remove-Item -Recurse -Force "$env:TEMP\electronegativity-watch-*", "$env:TEMP\electronegativity-remote-*"
Remove-Variable Cookie -ErrorAction SilentlyContinue
```

Delete the marker documents from the test environment if others use it.
