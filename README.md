# Electronegativity

⚠️ **We're no longer actively maintaining this project** ⚠️ 

## What's Electronegativity?

**Electronegativity** is a tool to identify misconfigurations and security anti-patterns in [Electron](https://electronjs.org/)-based applications.
<p align="center">
	<img src="https://github.com/doyensec/electronegativity/raw/master/docs/resources/img/electronegalogo.png">
</p>

It leverages AST and DOM parsing to look for security-relevant configurations, as described in the ["Electron Security Checklist - A Guide for Developers and Auditors"](https://doyensec.com/resources/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf) whitepaper.

Software developers and security auditors can use this tool to detect and mitigate potential weaknesses and implementation bugs when developing applications using Electron. A good understanding of Electron (in)security is still required when using Electronegativity, as some of the potential issues detected by the tool require manual investigation.

If you're interested in Electron Security, have a look at our *BlackHat 2017* research [Electronegativity - A Study of Electron Security](https://doyensec.com/resources/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security.pdf) and keep an eye on the [Doyensec's blog](http://blog.doyensec.com).

![Electronegativity Demo](https://github.com/doyensec/electronegativity/raw/master/docs/resources/img/electrodemo.gif "Electronegativity Demo")


## ElectroNG Improved Version
If you need something more powerful or updated, an improved SAST tool based on Electronegativity is available as the result of many years of applied R&D from [Doyensec](https://doyensec.com/). At the end of 2020, we sat down to create a project roadmap and created a development team to work on what is now [ElectroNG](https://get-electrong.com). You can read more some of the major improvements over the OSS version in a recent [blog post](https://blog.doyensec.com/2022/09/06/electrong-launch.html). 

<p align="center">
  <img src="https://get-electrong.com/img/lead.png">
</p>

## Installation

Electronegativity requires Node.js `^22.18.0` or `>=24.11.0`. It is not published to NPM; install it straight from GitHub instead.

Install the `electronegativity` command globally:

```
$ npm install -g github:Headset365/electronegativity
$ electronegativity -h
```

Or run it from a clone, with no build step:

```
$ git clone https://github.com/Headset365/electronegativity.git
$ cd electronegativity
$ npm ci
$ node src/index.js -i /path/to/electron/app
```

To update a global install, run the `npm install -g` command again.

Installing from GitHub needs Git on the PATH (`winget install --id Git.Git -e` on Windows). Without Git, install the branch archive instead: `npm install -g https://github.com/Headset365/electronegativity/archive/refs/heads/<branch>.tar.gz`.

In PowerShell, quote comma-separated lists (`-o "report.html,report.json"`): unquoted, PowerShell passes them space-separated, which the tool also accepts. Run it from a folder you can write to; the reports' folder is checked before the scan starts.

### What's new in 2.0

* Supports modern Electron projects: `.mjs`/`.cjs`/`.mts`/`.cts` sources, current ECMAScript and TypeScript syntax, and Electron versions detected from `package-lock.json` (v1-v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` and `node_modules/electron`.
* Checks account for the secure defaults of newer Electron releases: `contextIsolation` (Electron 12+), `sandbox` (Electron 20+, unless `nodeIntegration` is enabled) and the removal of the `remote` module (Electron 14+). When the Electron version can't be detected, the oldest (least secure) defaults are still assumed.
* `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK` now queries the [OSV](https://osv.dev) database of published Electron security advisories (GitHub Security Advisories), as Electron's former release feed stopped being updated in 2022. Findings list the matching advisory IDs.
* Native ES modules with no build step, running on current versions of all dependencies (Babel 8, TypeScript ESTree 8, espree, eslint-scope, cheerio 1.x, commander, chalk).
* 96 security checks (up from 42), covering the current [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security): IPC sender validation, APIs exposed through `contextBridge`, Electron Fuses, `setWindowOpenHandler`, `<webview>` hardening, custom scheme privileges, disabled TLS validation, `shell` APIs, deep link and file association handlers, downloads, update feeds, plaintext secrets, screen capture, DevTools, Secure Keyboard Entry, WebGL/WebSQL, unsandboxed iframes, HTML injection into AngularJS and rich-text editors (including AngularJS compiling markup built from data, the template injection behind Grafana's CVE-2020-12052), sanitizer and editor configuration that lets script through (DOMPurify, AngularJS `$sanitize`, TinyMCE, CKEditor, Froala, Summernote), AngularJS `$sce` configuration and certificate pinning. HTML sinks are raised to HIGH when their content comes from the server, a paste or drop, the clipboard or an imported document (`.docx` converted with mammoth, files read with `FileReader`).
* Outdated software: end-of-life Electron majors, newer patch releases of pinned versions, and known vulnerabilities in every locked npm dependency. Development-only packages are reported as LOW: npm lockfiles record them, and for Yarn and pnpm lockfiles they are worked out from the `dependencies` of the project's `package.json` files and workspaces.
* Findings follow the Electron version in use, e.g. `affinity` is ignored from Electron 14 and the `new-window` event is reported as ineffective from Electron 22.
* Upgrade checks (`-u`) for the breaking changes of Electron 12 to 32.
* A self-contained, filterable HTML report (`-o report.html`) and JSON output, next to CSV and SARIF. The HTML report opens with the renderer attack surface: every window with its effective `nodeIntegration`, `contextIsolation`, `sandbox` and `webSecurity` settings and what page script could reach in it, and the APIs each preload script exposes to web content.
* Cross-file analysis: handlers, helpers and constants imported from other files (ES modules, CommonJS, re-exports, `tsconfig.json` `baseUrl`/`paths` aliases) and handler factories are followed. Window options merged from shared defaults (`{ ...defaults }`, `Object.assign({}, defaults, options)`, `Object.freeze(...)`, also across files) and data from IPC, navigation and deep link handlers is followed into the helpers it is passed to, across files and up to six calls deep. A helper parameter that every caller in the project sets to a constant is reported as LOW. Minified bundles (`new o.BrowserWindow(...)`, `!0`/`!1`) are understood, and inline `<script>` blocks of HTML files go through the JavaScript checks.
* Baselines (`--baseline`, `--write-baseline`) and a CI exit code (`--fail-on`), see [CI](#cicd).
* In source folders, tests, fixtures, vendored code, tooling folders (`scripts`, `tools`, dot-folders) and minified files are skipped by default (`--all-files` to include them). In a packaged app (`app.asar`, `resources/app`) and in front-end code downloaded from a server, everything that ships is scanned, including `scripts/` and `.min.js` bundles, and the packages in its `node_modules` stand in for the missing lockfile in the dependency advisory and end-of-life checks. Bundles of libraries (`vendor.min.js`, `chunk-vendors.js`) are recognized by the banner of the first library. Vendored code includes bower and jspm folders (`.bowerrc`) and copied libraries, recognized by a header comment naming the file with a version and license (e.g. `js/jquery.js`).
* Validated on Signal Desktop, Element, VS Code, Mattermost, GitHub Desktop, Hyper and Electron Fiddle: no parse errors, and the remaining HIGH findings were confirmed by hand. Cross-checked against old releases with published vulnerabilities, see [Known vulnerabilities](#known-vulnerabilities).

### Merged from Electron-Dynamic

The black-box side of [Electron-Dynamic](https://github.com/Headset365/Electron-Dynamic) (`electron-audit`) now lives here, in JavaScript and with no new dependencies:

* **Installers and packages** (`-i Setup.exe`): electron-builder NSIS installers and portable executables (solid or not, deflate or LZMA; the app-*.7z inside, with its own pure-JavaScript 7z / LZMA / LZMA2 / BCJ / BCJ2 reader), Squirrel.Windows `Setup.exe`, `.7z`, `.zip` and `.nupkg`. The installer's own signature, the URL protocols and file types it registers, and web installers' package URLs are reported. See [Installers and packages](#installers-and-packages).
* **Traffic checks**: cleartext HTTP and WebSockets, secrets in URLs, responses and WebSocket messages, credentials or user input sent to third parties, IDOR candidates, reflected input, Basic auth and cookie flags, on a saved capture (`--ingest capture.har` or Burp XML) or live in watch mode, where every window's DevTools protocol connection, the session's `webRequest` events and the main process's Node `http`/`https` feed them. Watch mode also reports secrets written to the consoles, uncaught exceptions and CSP violations. See [Traffic](#traffic).
* **Data at rest** (`--user-data`, and after every watch session): secrets in Local Storage, Session Storage and IndexedDB (a read-only LevelDB reader) and unencrypted cookies, and **where a remembered password went** (`--canary`): plaintext, UTF-16, base64 at any offset, hex, URL encoding, decoded LevelDB stores and the Windows registry, with a before/after comparison of the app's folders and the Credential Manager. See [Data at rest](#data-at-rest).
* **Storage and secrets in code**: files written with secrets, `electron-store` without (or with a constant) `encryptionKey`, cookies set without their flags, a *Saved credentials* inventory of every read and write of a credential with its protection, and hard-coded secrets (provider keys, secret-named assignments, entropy in configuration files, native modules and helper binaries).
* **The packaged executable**: app.asar compared with the integrity hash embedded at build time, the code signature (verified by Windows or macOS when the scan runs there), exploit mitigations (ASLR, DEP, CFG; PIE, NX, RELRO), and `resources/app-update.yml`.
* **Vulnerability intelligence**: CISA KEV (exploited in the wild) and FIRST EPSS on every advisory, malicious package versions, and the Chromium CVEs the bundled Chromium misses, minus the fixes Electron's release notes say were backported.
* **Reports**: a Word report (`-o report.docx`) grouped by who can exploit each finding, with Appendix A of outdated components; client findings grouped by problem in Markdown (`-o findings.md`) and an outdated-components spreadsheet (`-o components.xlsx`); a CycloneDX 1.5 SBOM (`-o report.cdx.json`); several outputs in one run (`-o report.html,findings.md,components.xlsx`); risk and external-only scores; your own notes per check (`--finding-notes`).
* **Triage**: accepted risks by check, file or text with an owner and an expiry date (`--suppress`), expiry dates on baseline entries, and a comparison with the previous scan (`--compare`). See [CI/CD](#cicd).

## Checks

Checks run on JavaScript/TypeScript, HTML, `package.json`/`electron-builder.json` and lockfiles. Global checks combine the findings of several files, e.g. to report a protection that is missing from the whole application.

| Area | Checks |
|---|---|
| Renderer isolation | `NODE_INTEGRATION_*`, `CONTEXT_ISOLATION_JS_CHECK`, `SANDBOX_*` (incl. `app.enableSandbox()`), `PRELOAD_JS_CHECK`, `REMOTE_MODULE_JS_CHECK` (incl. `@electron/remote`), `AFFINITY_*` |
| IPC and preload | `IPC_SENDER_VALIDATION_JS_CHECK`, `CONTEXT_BRIDGE_EXPOSURE_JS_CHECK`, `IPC_HANDLER_JS_CHECK` (what each handler does: files, processes, shell, network, windows, credentials; unchecked arguments, a window chosen by the page, credentials sent back), `IPC_FILE_ACCESS_JS_CHECK` (paths from a page, a navigation or a deep link reaching `fs`: traversal, absolute and UNC paths; Windows reserved names, streams and trailing dots when only `path.basename` guards it), `IPC_CHANNEL_MAP_GLOBAL_CHECK` (each channel's handler, the preloads that send it and the windows loading them; handled channels nothing sends) |
| Binary hardening | `FUSES_JS_CHECK`, `FUSES_JSON_CHECK`, `FUSES_GLOBAL_CHECK` (RunAsNode, NODE_OPTIONS, `--inspect`, ASAR integrity, cookie encryption, ...) |
| Web security | `WEB_SECURITY_*`, `INSECURE_CONTENT_*`, `HTTP_RESOURCES_*`, `CSP_*`, `EXPERIMENTAL_FEATURES_*`, `BLINK_FEATURES_*`, `WEBGL_*`, `WEBSQL_*`, `PLUGINS_*`, `NAVIGATE_ON_DRAG_DROP_*`, `CSP_DIRECTIVES_GLOBAL_CHECK` (frame-src, connect-src, img-src, style-src, form-action; one policy for every page), `XSS_SINK_JS_CHECK` (DOM, React and jQuery sinks; server-fed HTML raised to HIGH), `RICH_TEXT_EDITOR_JS_CHECK`, `ANGULAR_TRUST_HTML_JS_CHECK`, `ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK`, `IFRAME_SANDBOX_*`, `ANGULAR_SCE_DISABLED_JS_CHECK`, `ANGULAR_RESOURCE_URL_LIST_JS_CHECK` |
| Navigation and windows | `NAVIGATION_REDIRECT_GLOBAL_CHECK` (a will-navigate allowlist that server redirects get around), `WINDOW_SESSION_GLOBAL_CHECK` (windows of different privilege sharing a session), `LIMIT_NAVIGATION_*`, `WINDOW_OPEN_HANDLER_JS_CHECK`, `UNTRUSTED_LOAD_URL_JS_CHECK`, `FILE_PROTOCOL_JS_CHECK`, `AUXCLICK_*`, `ALLOWPOPUPS_HTML_CHECK`, `WEBVIEW_TAG_JS_CHECK`, `WEBVIEW_GLOBAL_CHECK` |
| Dangerous APIs | `DANGEROUS_FUNCTIONS_JS_CHECK`, `OPEN_EXTERNAL_JS_CHECK`, `OPEN_PATH_JS_CHECK`, `SHOWITEMINFOLDER_JS_CHECK`, `WRITE_SHORTCUT_JS_CHECK`, `COMMAND_INJECTION_JS_CHECK`, `DEVTOOLS_JS_CHECK` |
| Protocols and external input | `PROTOCOL_HANDLER_JS_CHECK`, `PROTOCOL_PRIVILEGES_JS_CHECK`, `FILE_HANDLER_JS_CHECK`, `FILE_HANDLER_JSON_CHECK`, `PERMISSION_REQUEST_HANDLER_*` |
| TLS | `CERTIFICATE_ERROR_EVENT_JS_CHECK`, `CERTIFICATE_VERIFY_PROC_JS_CHECK`, `CERTIFICATE_PINNING_GLOBAL_CHECK`, `NODE_TLS_REJECT_UNAUTHORIZED_*` |
| Configuration | `CUSTOM_ARGUMENTS_*`, `SECURITY_WARNINGS_DISABLED_*`, `SECUREKEYBOARDENTRY_*`, `PLAINTEXT_SECRETS_JS_CHECK` |
| Production build | `DEVELOPMENT_CODE_JS_CHECK` (local dev servers, dev tooling, extension installers; dev-only IPC channels, preload APIs and switches turned on by an environment variable or flag instead of `app.isPackaged`), `DEBUG_LOGGING_JS_CHECK`, `SOURCE_MAP_SHIPPED` (maps in a packaged app, with the original sources or not; `-l`/`-x SourceMapsCheck`) |
| Documents and Word | `WORD_LAUNCH_JS_CHECK` (how Word is found: fixed path, registry or PATH; document names from content on its command line or through a shell; `/m` `/t` switches; `ms-word:` URIs built from content; documents opened with their default program), `DOCUMENT_PIPELINE_JS_CHECK` (DOCX, XML, ZIP, Markdown, PDF and SVG libraries by process; libxml2 `noent`/`dtdload`, mammoth `externalFileAccess`, markdown-it `html: true`, zip slip) |
| Downloads and updates | `DOWNLOAD_JS_CHECK` (auto-opened downloads, server-chosen file names), `UPDATE_SECURITY_*` (HTTP feeds, unverified signatures, downgrades) |
| Outdated software | `ELECTRON_VERSION_JSON_CHECK`, `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK`, `UNSUPPORTED_VERSION_GLOBAL_CHECK`, `DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK` (also for library copies bundled with the app), `END_OF_LIFE_LIBRARY_GLOBAL_CHECK` (AngularJS, jQuery 1.x/2.x, Bootstrap 2-4; works offline) |
| Attack surface inventory | `WINDOW_SUMMARY_JS_CHECK`, `EXPOSED_API_JS_CHECK`, `GLOBAL_EXPOSURE_JS_CHECK` (direct window/globalThis assignments; informational, context-dependent) |
| Storage and secrets | `PLAINTEXT_SECRETS_JS_CHECK`, `SECRET_FILE_WRITE_JS_CHECK`, `ELECTRON_STORE_ENCRYPTION_JS_CHECK`, `COOKIE_FLAGS_JS_CHECK`, `CREDENTIAL_ACCESS_JS_CHECK` (the *Saved credentials* table), `HARDCODED_SECRET` (code, configuration files, native modules and helper binaries; `-l`/`-x HardcodedSecretsCheck`) |
| Packaged executable | `ASAR_INTEGRITY`, `CODE_SIGNING`, `BINARY_HARDENING`, `UPDATE_SECURITY_PACKAGED` (`-l`/`-x PackagedBinaryCheck`); for installers `INSTALLER_FILE_HANDLER` |
| Vulnerability intelligence | `MALICIOUS_DEPENDENCY`, `CHROMIUM_ADVISORIES` (with an HTML or JSON report: KEV and EPSS in the dependency table) |
| Traffic (`--ingest`, `--watch`) | `TRAFFIC_CLEARTEXT_HTTP`, `TRAFFIC_SECRET_IN_URL`, `TRAFFIC_AUTH_TO_THIRD_PARTY`, `TRAFFIC_USER_INPUT_TO_THIRD_PARTY`, `TRAFFIC_STATE_CHANGE_NO_AUTH`, `TRAFFIC_IDOR_CANDIDATE`, `TRAFFIC_REFLECTED_INPUT`, `TRAFFIC_BASIC_AUTH`, `TRAFFIC_SECRET_IN_RESPONSE`, `TRAFFIC_INSECURE_COOKIE`, `TRAFFIC_WS_CLEARTEXT`, `TRAFFIC_WS_SECRET_IN_URL`, `TRAFFIC_WS_HTML_MESSAGE`, `TRAFFIC_WS_SECRET_IN_MESSAGE` |
| Data at rest (`--user-data`, `--canary`, `--watch`) | `STORAGE_CACHED_RESPONSES` (Cache Storage and the HTTP cache), `STORAGE_SECRET_AT_REST`, `STORAGE_COOKIE_AT_REST`, `STORAGE_CREDENTIAL_AT_REST`, `STORAGE_CREDENTIAL_TRACE` |
| Runtime (`--watch`) | `RUNTIME_PRELOAD_FOREIGN_ORIGIN`, `RUNTIME_REDIRECT`, `RUNTIME_WINDOW_SESSION`, `RUNTIME_SECRET_IN_CONSOLE`, `RUNTIME_UNCAUGHT_EXCEPTION`, `RUNTIME_CSP_VIOLATION`, `RUNTIME_NODE_INTEGRATION`, `RUNTIME_CONTEXT_ISOLATION`, `RUNTIME_SANDBOX`, `RUNTIME_WEB_SECURITY`, `RUNTIME_CSP`, `RUNTIME_INSECURE_LOAD`, `RUNTIME_NAVIGATION`, `RUNTIME_NEW_WINDOW`, `RUNTIME_WEBVIEW`, `RUNTIME_OPEN_EXTERNAL`, `RUNTIME_OPEN_PATH`, `RUNTIME_PERMISSION`, `RUNTIME_PERMISSION_CHECK`, `RUNTIME_CERTIFICATE_ERROR`, `RUNTIME_DOM_INJECTION`, `RUNTIME_MARKER`, `RUNTIME_CAMPAIGN_*`, `RUNTIME_IPC`, `RUNTIME_COVERAGE`, `RUNTIME_WINDOW_COVERAGE`, `PACKAGED_FUSES` |

The outdated software checks need network access: they query [releases.electronjs.org](https://releases.electronjs.org) (cached for 12 hours) and the [OSV](https://osv.dev) vulnerability database. Offline, they print a warning and are skipped; `--offline` skips them without trying.

### Confidence

Every finding has a confidence level:

* **CERTAIN**: the insecure setting or behavior is stated in the code, e.g. `webSecurity: false`, a permission handler that calls `callback(true)` unconditionally, or a `will-navigate` handler that never calls `event.preventDefault()`.
* **FIRM**: the code analysis shows the problem, but it depends on something that can't be fully proven statically, e.g. an `openExternal()` argument that flows from an IPC handler parameter, or a handler that only allows some URLs.
* **TENTATIVE**: the relevant value isn't known at all, e.g. a setting taken from a variable defined in another file.

Rather than flagging every use of a sensitive API, checks look at what the code does with it: they resolve constants, follow values from handler parameters through local variables, recognize URL validation (`new URL()`, origin/protocol checks, allowlists) and tell conditional code from unconditional code. A setting that is secure by default in the Electron version in use is not reported.

### Test coverage

`test/test_checklist.js` covers each item of the [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security) and the other practices above with an insecure example, which must be reported with the expected severity and confidence, and a secure one, which must not be. `test/apps` contains a hardened sample app, which must only produce low-severity "review the allowlist" notes, and a vulnerable one, which must trigger each check with a firm or certain confidence. Every finding links to documentation of the problem; `npm run check:references` (needs network access) verifies that each linked page, and the section it points to, still exists.

### Known vulnerabilities

The root cause of each published vulnerability below is reported when scanning the affected release, offline:

| Release | Vulnerability | Reported |
|---|---|---|
| Signal Desktop 1.10.0 | CVE-2018-10994: XSS in messages, `body.html(Signal.HTML.render(escapedBody))` | `XSS_SINK_JS_CHECK` at `js/views/message_view.js:511` (render re-introduces markup after escaping) |
| Signal Desktop 1.10.0 | CVE-2018-11101: XSS in quoted replies | `XSS_SINK_JS_CHECK` (`dangerouslySetInnerHTML`) at `Quote.tsx:114`; `CONTEXT_ISOLATION_JS_CHECK` HIGH (Electron 1.8 default) |
| Jitsi Meet Electron 2.0.0 | CVE-2020-25019: `shell.openExternal` on any link | `OPEN_EXTERNAL_JS_CHECK` HIGH/FIRM at `main.js:165` (value from `new-window`, not validated) |
| MarkText 0.16.3 | CVE-2021-29996, CVE-2023-2318: XSS to RCE (paste handling, `nodeIntegration`) | `NODE_INTEGRATION_JS_CHECK` and `CONTEXT_ISOLATION_JS_CHECK` HIGH/CERTAIN (options merged from `config.js`), `WEB_SECURITY_JS_CHECK`, `XSS_SINK_JS_CHECK` at `pasteCtrl.js:54` |
| Joplin 2.8.8 | CVE-2022-35131 and later note-viewer XSS to RCE | `NODE_INTEGRATION_JS_CHECK` and `CONTEXT_ISOLATION_JS_CHECK` HIGH/CERTAIN, `XSS_SINK_JS_CHECK` in the note viewer's inline script, `IFRAME_SANDBOX_JS_CHECK` for the unsandboxed viewer frame, raised to MEDIUM because the window enables `nodeIntegration` |
| Element Desktop 1.9.6 | CVE-2022-23597: deep links loaded into the main window | `UNTRUSTED_LOAD_URL_JS_CHECK` HIGH/FIRM at `protocol.ts:32`, no longer reported on the fixed 1.9.7 |
| Grafana 6.7.1 (AngularJS front end) | CVE-2020-12052: stored XSS in annotation popups, sanitized text compiled as an AngularJS template | `ANGULAR_TRUST_HTML_JS_CHECK` at `annotation_tooltip.ts:92` (`$compile` of an element holding markup built from data), no longer reported on the fixed 6.7.4 (`ng-non-bindable`) |

With network access, the same releases are also reported as end-of-life, with the Electron advisories that affect them (the list matches a direct OSV query, e.g. all 48 advisories for Electron 1.8.4, including CVE-2018-15685):

| Release | Electron | Electron advisories | Dependency advisories (runtime / development) |
|---|---|---|---|
| Signal Desktop 1.10.0 | 1.8.4 | 48 | 39 / 158 |
| Jitsi Meet Electron 2.0.0 | 8.2.1 | 49 | 27 / 52 |
| MarkText 0.16.3 | 11.1.1 | 42 | 51 / 126 |
| Element Desktop 1.9.6 | 13.5.1 | 41 | 16 / 39 |
| Joplin 2.8.8 | 14.1.0 | 41 | 119 / 82 |

Advisory counts grow as new advisories are published.

## Usage

### CLI

```
$ electronegativity -h
```

|    Option    |                 Description                       |
|:------------:|:-------------------------------------------------:|
| -V           | output the version number                         |
| -i, --input  | input (directory, .js, .html, .asar, an installed app's folder or executable, or an installer or package: NSIS or Squirrel `.exe`, `.7z`, `.zip`, `.nupkg`) |
| --app <location> | guided run: find the app in this install folder (or its executable), scan it, then walk through watch sessions, writing every report to one results folder |
| --out <dir> | results folder for `--app` (default `electronegativity-results-<date>`) |
| --report-dir [folder] | every run already puts its reports in a new folder named `electronegativity-<UTC date and time>`, made in the folder you ran the tool from; give a folder to make it there instead, see [Report folder](#report-folder) |
| --no-report-dir | don't create that folder; write only the outputs you ask for |
| --sessions <count> | number of watch sessions `--app` runs without asking (`0` for the static scan only) |
| -l, --checks | only run the specified checks, passed in csv format |
| -x, --exclude-checks <excludedCheckNames> | skip the specified checks list, passed in csv format |
| -s, --severity | only return findings with the specified level of severity or above |
| -c, --confidence | only return findings with the specified level of confidence or above |
| -o, --output <filename> | save the results to a file: `.html` report, `.json`, `.sarif`, `.csv`, `.docx` (Word report), `.md` (client findings), `.xlsx` (outdated components) or `.cdx.json` (CycloneDX SBOM); several at once separated by commas. The `-s` and `-c` thresholds apply |
| -r, --relative | show relative path for files |
| -v, --verbose <bool> | show the description for the findings, defaults to true |
| -u, --upgrade <current version..target version> | run Electron upgrade checks, eg -u 22..32 to check an upgrade from Electron 22 to 32 (covers Electron 5 to 32) |
| -e, --electron-version <version> | assume the set Electron version, overriding the detected one, eg -e 7.0.0 to treat as using Electron 7 |
| -p, --parser-plugins <plugins> | specify additional parser plugins to use separated by commas, e.g. -p optionalChaining |
| --offline | skip the checks that need network access (Electron releases and security advisories) |
| --all-files | also scan tests, fixtures, vendored, tooling and minified files (skipped by default) |
| --baseline <file> | don't report the findings accepted in this baseline file |
| --write-baseline <file> | write the current findings to a baseline file (reasons already recorded are kept) |
| --fail-on <severity> | exit with code 1 when a reported finding has this severity or higher (`high`, `medium`, `low`, `informational`); 2 for invalid arguments |
| --remote <url> | also scan the front end served at this URL: its page, scripts, source maps and the templates and chunks the code names (can be repeated) |
| --remote-header <header> | header sent with `--remote` and watch-mode downloads to the same site, e.g. `"Cookie: session=..."` for a test account (can be repeated) |
| --ingest <file> | run the traffic checks on a saved capture: a HAR file or Burp Suite "Save items" XML (can be repeated; works without `-i`), see [Traffic](#traffic) |
| --scope <domain> | a domain the app itself uses, for the traffic checks to tell its hosts from third parties (learned from the traffic when not given; can be repeated) |
| --no-watch-traffic | in watch mode, don't run the traffic checks inside the app |
| --watch-screenshots [dir] | in watch mode, save a screenshot of the window as evidence when the marker comes back as live HTML, script is inserted into a page or a navigation carries the marker (default `./screenshots`, or inside the `--app` results folder). Off by default: pages can show confidential data |
| --active-tests | opt in to a benign HTML event-handler probe during `--watch` or `--app`; the report records execution only if the renderer emits its unique signal |
| --campaign <file> | run the bounded payload suite from an explicit test profile; saves/reopens cases without per-case prompts |
| --user-data <dir> | review the app's profile folder for secrets at rest; `auto` finds it by the app's name (watch mode reviews it after the session), see [Data at rest](#data-at-rest) |
| --canary <password> | a unique test password typed into the app with "remember me": find where it was stored and whether it is encrypted (can be repeated) |
| --search-dir <dir> | another folder to search for the `--canary` password (can be repeated) |
| --show-secrets | keep the full values of secrets in the report instead of a redacted prefix: secrets found at rest, in request URLs, headers and responses, and in console output (don't share such a report; its shareable report leaves out code samples) |
| --no-nvd | don't look up the Chromium CVEs of the app's Electron version in NVD |
| --finding-notes <file> | your own notes per check or family, shown in the HTML, JSON and Word reports (see `docs/finding-notes.example.json`) |
| --suppress <file> | accepted risks by fingerprint, check or file, with a reason, owner and expiry date (see `docs/suppressions.example.json`) |
| --compare <report> | an earlier JSON report: mark each finding new, unchanged or changed, and list what was fixed |
| --share <file> | write the findings redacted for sharing (Markdown, or JSON for `.json`), see [Sharing findings](#sharing-findings); with `--app`, one per step |
| --share-code | include each finding's code in the `--share` report, strings and comments masked |
| --diagnostics <file> | write a sanitized troubleshooting report, see [Diagnostics](#diagnostics) |
| --redact <terms> | extra terms to remove from the diagnostics report, comma separated |
| -h, --help   | output usage information                          |


Using electronegativity to look for issues in a directory containing an Electron app:
```
$ electronegativity -i /path/to/electron/app
```

Using electronegativity to look for issues in an `asar` archive and saving the results in an HTML report:
```
$ electronegativity -i /path/to/asar/archive -o report.html
```

The HTML report is a single file with no external resources. It summarizes the findings by severity and check, and can be filtered by severity, confidence, check, manual review status and free text. Each finding says what it means in practice, who could exploit it (content another user can place in the app, a network position, local access, ...) and what the victim has to do (view the content, click a link, open a file; `interaction` in JSON), and its code sample is collapsed until opened. The header gives the Chromium, Node.js, V8 and OpenSSL versions the Electron release bundles.

HTML and JSON reports also include a dependency table: every npm package (from the lockfile, or the `node_modules` of a packaged app), every library copy or bundle recognized by its banner or version string (jQuery, AngularJS, TinyMCE, CKEditor, DOMPurify, lodash, ..., including scripts loaded from a server with `--remote` or watch mode) and the Electron runtime. For each, it gives the release date of the version found, the latest version and its release date, how many releases and major versions behind it is, whether its release line is supported (from [endoflife.date](https://endoflife.date) where the project publishes a policy, otherwise npm deprecation and the latest major line), and the advisories that affect it with their CVE ids and fixed versions (from [OSV](https://osv.dev)). With `--offline` the table lists the versions found without looking anything up.

Using electronegativity when upgrading from one version of Electron to another to find breaking changes:
```
$ electronegativity -i /path/to/electron/app -v -u 22..32
```

Note: if you're running into the Fatal Error "JavaScript heap out of memory", you can run node using ```node --max-old-space-size=4096 electronegativity -i /path/to/asar/archive -o result.csv```

### Installers and packages

Point `-i` at what the vendor ships: the app inside is unpacked to a temporary folder and scanned, with its executable, and the installer reports on itself.

```
$ electronegativity -i MyApp-Setup-1.2.3.exe -o report.html,report.docx
```

NSIS installers built by electron-builder (solid or not, zlib/deflate or LZMA; with bzip2 the script header can't be read, but the stored app still is) and portable executables, Squirrel.Windows `Setup.exe` (the `.nupkg` in its resources), and `.7z`, `.zip` and `.nupkg` packages are read in JavaScript, on any host. A multi-architecture installer is scanned through its x64 app. NSIS web installers download the app at install time: the tool names the package URL instead. Encrypted 7z archives are refused. The installer's signature (`CODE_SIGNING`), the URL protocols and file types it registers (`INSTALLER_FILE_HANDLER`), its size and SHA-256 are reported.

### Traffic

The traffic checks look at what the app sends and receives, without sending anything themselves:

```
$ electronegativity --ingest capture.har -o report.html                    # a HAR from DevTools or a proxy
$ electronegativity -i ./MyApp --ingest burp-items.xml --scope example.com  # Burp "Save items", with the code
```

Watch mode runs the same checks inside the app during the session: each window's DevTools protocol connection gives the headers actually sent (cookies included), response headers and text bodies, and WebSocket frames; the session's `webRequest` events cover requests no window sees (`electron.net`, service workers); the main process's Node `http`/`https` and global `fetch` (through undici's diagnostics channels) are observed too (headers only). Only the findings leave the app, with secrets reduced to a short prefix. When the app attaches its own debugger to a window, the observer steps aside for that window. The first-party scope is the site the app's windows load and the hosts that set its cookies, or `--scope`. A Burp capture of https traffic also confirms `CERTIFICATE_PINNING_GLOBAL_CHECK`: the proxy's certificate was accepted.

### Data at rest

```
$ electronegativity --watch "C:\Program Files\MyApp" --canary "Zq7-test-Pw!2026" -o report.html
$ electronegativity -i ./MyApp --user-data "%APPDATA%\MyApp" -o report.html
```

After a watch session (or with `--user-data`), the app's profile folder is read, never written: Local Storage, Session Storage and IndexedDB are decoded (LevelDB, Snappy included) and searched for secrets, the cookie store (read from a copy, with Node's SQLite) for cookies kept unencrypted or under Chromium's fixed-key fallback, and the responses kept in Cache Storage and the HTTP cache (counted by host, and searched for secrets). With `--canary`, type a unique throwaway password into the app's login with "remember me" ticked, and pass the same value: the app's folders (`%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%` and `~/.config` by app, package and publisher name, the updater folder, dot-folders, the install folder, the profile the app reported, `--search-dir`) and its `HKCU\Software` key are searched for it in plaintext and reversible encodings. In watch mode the folders and the Windows Credential Manager are recorded before the app starts, so when the password isn't found the report shows where the app did write, and which files hold DPAPI or safeStorage ciphertext. Nothing is decrypted, and values are redacted unless `--show-secrets` is given.

### Guided run of an installed app

Point `--app` at where the app is installed and it does the rest:

```
$ electronegativity --app "C:\Program Files\MyApp"
```

It finds the executable and `resources\app.asar` (install folders, the executable itself, Squirrel's `app-<version>` folders, or the folder holding the install folder), scans the app's code, then offers watch sessions one at a time: the app opens, you log in and use it, close it, and it asks whether to run another (for example as a second account). A planted-content marker is generated for the run (or give one with `--watch-marker`). Each step writes its report and a diagnostics file into one results folder (`--out`). `--remote`, `--remote-header`, `--offline`, `--redact`, `--watch-args` and the filtering options apply as usual. `-i` and `--watch` also accept an install folder or executable.

### Front end served remotely

Many Electron apps load their interface from a server (`win.loadURL('https://app.example.com')`), so the code that renders other people's content isn't in the app package. `--remote` downloads it and scans it with the app:

```
$ electronegativity -i ./my-app --remote https://test.example.com/ --remote-header "Cookie: session=..." -o report.html
```

The page, its scripts and the HTML templates and chunks the code names (AngularJS `templateUrl`, `ng-include`, lazy `import()`s) are fetched from the same site. When a script has a source map with the original sources, those are scanned instead of the minified bundle, which the checks follow far better. Findings point at the URL the file was served from, e.g. `https://test.example.com/static/app.js (source: src/editor/paste.js)`. Headers are only sent to the site given, never to third-party script hosts. Watch mode does the same automatically for the pages you open (see below). A test server whose certificate comes from an internal CA needs `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for `--remote` (watch mode downloads through the app, which already trusts it).

### Watch mode (runtime observation)

Static analysis reads all the code, including the parts behind a login. Watch mode adds what actually happens when the app runs: settings computed at runtime, the Content Security Policy each page really gets, and which IPC channels your session exercised.

```
$ electronegativity --watch ./my-app -o report.html          # app folder with Electron installed
$ electronegativity --watch ./dist/linux-unpacked/my-app -o report.html   # packaged executable
$ electronegativity --watch ./my-app --watch-marker ENGTEST42 -o report.html  # trace marker content
$ electronegativity --watch ./my-app --active-tests -o report.html  # opt-in benign execution probe
$ electronegativity --app ./my-app --campaign docs/campaign.example.json --out test-results  # configured campaign
$ electronegativity --watch-log session.jsonl -i ./my-app -o report.html  # re-analyze an earlier session
```

The app starts with a small observer loaded into its main process, and a read-only script installed in each page. Log in and go through the features you want covered, then close the app. The report then includes:

* every page each window showed, with the `nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity` values, the preload script it ran with and its session, linked to where the window is defined in the code;
* pages from another origin than their window started on that still ran its preload, server redirects windows followed to other origins, and windows of different privilege sharing a session;
* pages shown without a Content Security Policy (header or `<meta>`), or with one allowing inline scripts or `eval`;
* content loaded over plain http, navigation to other origins, new windows and `<webview>`s created for web content;
* `shell.openExternal` calls with non-web URLs and `shell.openPath` on executable file types;
* permissions granted automatically because the app has no permission request or check handler, and certificate errors;
* what the renderer-side observer saw inside pages: script-bearing DOM changes (`on*` handlers, `javascript:` URLs) and, with `--watch-marker`, whether a planted marker appeared as markup or text; these observations alone do not prove script execution;
* for a packaged app, the Electron Fuses read from the shipped binary, not only from the build configuration;
* coverage: IPC channels not seen during the session, window definitions without a unique runtime match, and marker sinks correlated to exact script lines;
* the front-end code pages ran, downloaded with the page's own session (so a logged-in test account works) and scanned statically, original sources included when there are source maps (`--no-watch-capture` to skip);
* the API endpoints pages called, grouped by route (`POST https://api.example.com/documents/{id}`), and which of them accepted HTML in the request body: where stored content enters, and where to start server-side testing (only whether a body looked like markup is recorded, never its content);
* the ways content came in during the session (paste, drag and drop, file pickers, deep links), and those the code handles that you never tried.

To trace stored content with `--watch-marker <token>`, put the token into the app and open the content in a watched page. HTML markup is a lead; text rendering on one page does not clear other routes. With `--active-tests`, a unique event-handler probe logs only `ENG_ACTIVE_EXEC:<token>` if it executes. On an interactive terminal the assistant offers to replay an observed JSON or form save request with this probe in HTML fields, after asking for that exact request. The probe is also written to a text file for fields the tool cannot replay. Use a disposable test record: replay can create or change saved content. A successful save without a renderer signal is reported as **not observed**, since the saved view may not have been opened. Execution confirms script ran in a watched renderer; the input route, account boundary and page privileges still need review.

#### Automated campaign profile

Copy [docs/campaign.example.json](docs/campaign.example.json) and set a **disposable test document**, its exact save request and field, and the view URL that opens the saved document. The app's test account/session must already be available. `--campaign` runs the configured cases sequentially through the app's Electron session, opens the view after each accepted save, restores the original request body, and closes the app after completion by default. Restoration failures are reported; `restoreOnDone: false` skips that final write. It does not ask for each case again. `request` mode needs no manual seed request; alternatively, replace `request` with `"capture": { "method": "PUT", "route": "https://app.test/api/documents/{id}" }` to reuse the first matching request observed during a session. Capture mode still needs that workflow to run once. Use `windowUrl` to select exactly one window when the app has several. A missing or ambiguous window stops the campaign with a coverage finding. Replace `field` with `"fields": ["body", "title"]` to test up to eight named fields, or `"fields": "auto"` to discover up to eight string fields in the declared request; automatic selection excludes names resembling IDs, credentials and control flags. Each field/case pair has its own signal and result. Use only a disposable record: auto discovery cannot know your business rules.

The default suite has 28 bounded text/HTML, script/event/SVG/URL, Node/Electron/temporary-file, `eval`, JSON type/size, external-resource and controlled renderer-data cases. The tool creates a random file canary in its own temporary folder and an ephemeral loopback resource receiver; it removes both after the run. For cookie, localStorage and IndexedDB probes it first plants a random value in the configured view, then tests whether document-delivered script reads **that value only**, and attempts cleanup. This establishes same-origin access to a tool-owned value, not access to real credentials or another account. The receiver records resource type and **presence** of Cookie/Authorization headers, never their values. A JSON type case requires a JSON request body. The campaign preserves other fields and even large numeric IDs byte-for-byte. Save results, view attempts, resource requests and execution signals are separate evidence. No signal means **not observed**, not a passing security check. Run it only against a test record: the suite overwrites the configured field repeatedly, and restoring the original body also sends a request. A successful script signal still needs the account/origin boundary and app-specific privileges checked. The 11 optional `api-*` cases require an explicit `api` contract, for example `{ "path": "api.openFile", "args": ["test.txt"], "mutationIndex": 0 }`; `api-loopback-url` can verify a request to the tool's receiver if the configured method accepts a URL. A returned promise alone is not a privileged effect. Use only a benign test method and arguments. Three optional navigation cases (`nav-loopback`, `nav-redirect`, `nav-data`) click a link delivered through the configured field and record whether the Electron window changed URL or the loopback receiver saw a request. They require a full `view` URL so the app can return after each case; they do not prove how an OS browser handled a link.

To test DOCX ingestion, use [docs/campaign.docx.example.json](docs/campaign.docx.example.json) with an exact multipart import endpoint and disposable import workspace. The tool creates six small Office Open XML fixtures (baseline, metadata, external relationship, SVG media, malformed XML and duplicate entry), posts them through the app session, opens the configured view and records accepted/rejected requests and any loopback relationship request. An HTTP success does **not** prove conversion, rendering, parser safety or that a relationship was followed. The generic runner cannot delete documents created by an unknown import API. A profile can contain both `request` and `docxImport` to run both suites in one session; a DOCX-only profile needs no save request. The configured `view` must be a usable page for each import; a dynamic document ID needs an app-specific adapter.

#### Validation assistant

With a marker (`--watch-marker`, or the one `--app` generates), watch mode follows the session and shows evidence and remaining coverage. In guided mode (`--app`) it starts from the static findings. A marker reaching a sink is labeled **observed**; only the opt-in probe's execution signal establishes script execution.

```
[validate] → Saw PUT https://api.example.com/matters/{id}/documents carrying HTML in: body; text in: title. Send it again with the marker: ENGK7Q2XM in the text fields and <span data-ENGK7Q2XM="1">ENGK7Q2XM</span> in body. Use the app (the editor's HTML/source view if it has one), or replay this request from your proxy.
[validate] ✓ The marker was sent with PUT https://api.example.com/matters/{id}/documents in: title, body (as HTML in: body). Now view that content: reload it here, or open it signed in as the second account.
[validate] ! Marker markup reached innerHTML by https://app.example.com/js/app.min.js:1:48213: observed XSS_SINK_JS_CHECK at https://app.example.com/js/app.min.js (source: src/documents/viewer.js):88. Script execution remains untested.
[validate] ! A link from content was handed to the operating system (shell.openExternal). Now try the same link as file:///C:/Windows/#ENGK7Q2XM: if a folder opens, the app passes links of any scheme to the OS.
[validate] → You pasted plain text. Also paste formatted content: open ...\ENGK7Q2XM-paste-me.html in a browser, select all, copy, and paste it here.
```

When it spots a save request carrying HTML, it can offer to replay the request with the marker or, with `--active-tests`, the benign execution probe in HTML fields. It shows the fields and endpoint and asks `y/N` for each request (default no). On yes, it uses that request's own session and headers; the body is rebuilt without rounding large integer IDs. It touches only HTML fields. It needs an interactive terminal and Electron 25+; JSON and urlencoded bodies are supported, while multipart uploads need another delivery route. No request body is written to the log or diagnostics report.

The passive marker has text, `<span>`, link and file forms. The observer records where it reaches request fields, HTML sinks, shell calls, navigation, IPC and process invocations. A matching script line or channel can be marked **Observed at runtime**. Other static findings stay open. The active probe has a separate **script executed** finding when its renderer signal appears, or an informational coverage finding when a save succeeded without an observed signal.

The observer records without changing the app's handling. Replayed requests require confirmation. URLs are stored without query strings, and IPC arguments only by type. An app folder loads the observer through `NODE_OPTIONS=--require`; a packaged app uses the local Node inspector and requires the `EnableNodeCliInspectArguments` fuse. Watch mode reports when it cannot attach. It scans the app folder or packaged `resources/app.asar` statically as well.

### Diagnostics

When a scan or a watch session doesn't behave as expected, `--diagnostics <file>` writes a report that can be shared for troubleshooting without sharing the app:

```
$ electronegativity -i ./my-app -o report.html --diagnostics diagnostics.json --redact "Acme,acme.internal"
```

It lists what was scanned (files by type), what was skipped and why (tests, bundled libraries, vendored folders), the Electron version and where it came from, files that could not be parsed, checks that failed (with the tool's own stack frames) and the slowest ones, network lookups that failed, finding counts per check and severity, and for watch mode whether the observer loaded, what it recorded and any errors inside it.

It never contains code, finding descriptions or data that passed through the app. The app's name (from `package.json` and the folder name, in its `-`, `_`, space and joined forms), the user name, the machine name and the home folder are replaced, as are the extra terms given with `--redact`; hosts in URLs are replaced by stable pseudonyms. Review the file before sharing it.

A check that crashes on a file no longer stops the other checks on that file: the failure is reported with the files that couldn't be analyzed, with or without `--diagnostics`.

### Remediation advice

Every finding that can be fixed comes with how to fix it: a short instruction and, for most checks, a code or configuration example (`contextIsolation`, IPC sender checks, the `shell.openExternal` and `shell.openPath` allowlists, fuses, CSP, permission handlers and so on). It appears as **How to fix** in the HTML report's finding groups, under **Recommendations** in the Word report (unless your `--finding-notes` give their own), as `remediation` and `remediationExample` in the JSON report, and as **How to fix** in the shareable report. Inventory and coverage findings have none. The advice is general guidance for the check, not a patch for your code: adapt the examples to the app before applying them, then re-scan with `--compare <earlier report.json>` to see what was fixed.

### Client findings and components

Write both client deliverables alongside the interactive report in one scan:

```sh
electronegativity -i ./my-app -o "report.html,findings.md,components.xlsx"
```

`findings.md` groups related checks in the client template, includes accepted risks from `--suppress` and `--baseline`, and links to `components.xlsx` when both are requested. It contains real names, paths, URLs and evidence. Each emitted group is one finding with labelled variations across all six sections; alternatives are tied to detected checks, and conditional implications can be removed when the client workflow rules them out. The spreadsheet lists only outdated, unsupported, deprecated, malicious or advisory-affected components, including development dependencies, bundled libraries and Electron when applicable. `--share` separately creates a redacted report for outside review.

### Sharing findings

To get help triaging a report without handing over the app, write a redacted copy of the findings:

```
$ electronegativity -i ./my-app -o report.html --share findings-share.md --redact "Acme,acme.internal"
```

It keeps the check, severity, confidence, potential input source, runtime status and evidence, relative file and line, description and check-specific details. Potential input source is a threat model, not a verified attacker capability. The Markdown and JSON reports list all findings, including informational inventories, with full arrays of check details.

Removed: the app, product, author and publisher names from `package.json` and the owner and domain in its homepage, repository, bugs and contact links, the app folder name, your user and machine names, the `--redact` terms, the home and user folders, hosts and bare domain names (replaced by stable pseudonyms such as `host-1a2b3c4d`; Electron and public documentation sites stay), UNC server names, ids (UUIDs), query strings, e-mail and IP addresses (loopback excepted) and anything matching a secret pattern. A final pass over the findings replaces any of these names that survived, and the JSON report's `audit.finalPassReplacements` counts them (normally 0). The Markdown opens with a note telling a reviewer or agent that the identity was removed on purpose. Code is left out; `--share-code` adds each finding's line with string literals and comments masked (short lowercase code tokens such as channel names, flags and file names stay). The redaction is pattern-based: read the file before sending it, and add names it missed to `--redact`.

### Report folder

Every run gets its own folder, made in the folder you ran the tool from, so runs never overwrite each other and everything for a run is in one place. `--report-dir <folder>` makes it inside another folder instead; `--no-report-dir` turns it off:

```
$ electronegativity -i ./my-app --redact "Acme,acme.internal"
Report folder: /home/me/electronegativity-2026-09-28T14-30-05Z
```

The folder (inside the folder you give, made if missing) holds:

| File | Content |
|---|---|
| `report.html`, `report.json` | the full report, for you (with app names and paths) |
| `shareable-report.md`, `shareable-report.json` | the findings with client information removed, to send to a reviewer or an AI agent, see [Sharing findings](#sharing-findings) |
| `diagnostics.json` | sanitized troubleshooting information |

Add `-o` or `--diagnostics` to write those files elsewhere as well. With `--app`, the results folder gets this name, with a Markdown and JSON shareable report per step (`static-share.md`, `session-1-share.json`...); With `--out <dir>` that folder is used instead of a new one. Nothing is created when the run ends before writing anything (no input, an unreadable installer). A second run in the same second gets `-2` after the name.

### Ignoring Lines or Files

Electronegativity lets you disable individual checks using `eng-disable` comments. For example, if you want a specific check to ignore a line of code, you can disable it as follows:

```js
const res = eval(safeVariable); /* eng-disable DANGEROUS_FUNCTIONS_JS_CHECK */
```

```html
<webview src="https://doyensec.com/" enableblinkfeatures="DangerousFeature"></webview> <!-- eng-disable BLINK_FEATURES_HTML_CHECK -->
```

Any `eng-disable` inline comment (`// eng-disable`, `/* eng-disable */`, `<!-- eng-disable -->`) will disable the specified check for just that line. It is also possible to provide multiple check names using both their snake case IDs (`DANGEROUS_FUNCTIONS_JS_CHECK`) or their construct names (`dangerousFunctionsJSCheck`):

```js
shell.openExternal(eval(safeVar)); /* eng-disable OPEN_EXTERNAL_JS_CHECK DANGEROUS_FUNCTIONS_JS_CHECK */
```

If you put an `eng-disable` directive before any code at the top of a `.js` or `.html` file, that will disable the passed checks for the *entire* file.
#### Note on Global Checks and `eng-disable` annotations
Before v1.9.0 Global Checks couldn't be disabled using code annotations. If you are still using an old version, use `-x` CLI argument to manually disable a list of checks instead (e.g. `-x LimitNavigationJsCheck,PermissionRequestHandlerJsCheck,CSPGlobalCheck`).
Note that using annotations may not be applicable for some higher-level checks such as `CSP_GLOBAL_CHECK` or `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK`. For those cases, you might want to use the `-x` flag to exclude specific checks from your scan.

### CI/CD

Review the findings once and record the accepted ones, with a reason, in a baseline:

```
$ electronegativity -i . --write-baseline .electronegativity-baseline.json
# edit the "reason" of each accepted finding, commit the file
```

Findings are matched by check, file and code, not by line number, so unrelated edits don't invalidate the baseline. Rewriting it keeps the recorded reasons, and scans report baseline entries that no longer match anything.

Then gate pull requests on new findings only:

```yaml
- run: npm install -g github:Headset365/electronegativity
- run: electronegativity -i . --baseline .electronegativity-baseline.json --fail-on medium -o electronegativity.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: electronegativity.sarif
```

The SARIF upload shows the findings as GitHub code scanning alerts, with stable fingerprints (`partialFingerprints`).

Baseline entries accept two optional fields, `owner` and `expires` (`YYYY-MM-DD`): an expired entry stops applying and its finding is reported again. To accept whole groups of findings, give a suppressions file with a reason for each rule, e.g. `{"check": "TRAFFIC_*", "file": "*.internal.example.com*", "reason": "internal test hosts", "owner": "platform", "expires": "2026-12-31"}` (see `docs/suppressions.example.json`): accepted findings are listed apart in the reports, marked as suppressed in SARIF, and don't count for the scores or `--fail-on`. `--compare previous.json` marks each finding new, unchanged or changed in severity (SARIF `baselineState`), adds a "New since the previous scan only" filter to the HTML report, and lists what was fixed.

```
$ electronegativity -i . --suppress accepted-risks.json --compare last-release.json -o report.json,report.html
```

### Programmatically

You can also use electronegativity programmatically, using similar options as for the CLI. Add it to your project from GitHub first (the package keeps the name `@doyensec/electronegativity`):

```
$ npm install github:Headset365/electronegativity
```

```js
const run = require('@doyensec/electronegativity')
// or: import run from '@doyensec/electronegativity';

run({
  // input (directory, .js, .ts, .html, .asar)
  input: '/path/to/electron/app',
  // save the results to a file (optional); the format follows the extension: .html, .json, .sarif or .csv
  output: '/path/for/output/report.html',
  // only run the specified checks (optional)
  customScan: ['dangerousfunctionsjscheck', 'remotemodulejscheck'],
  // skip the specified checks (optional)
  excludeFromScan: ['devtoolsjscheck'],
  // only return findings with the specified level of severity or above (optional)
  severitySet: 'high',
  // only return findings with the specified level of confidence or above (optional)
  confidenceSet: 'firm',
  // show relative path for files (optional)
  isRelative: true,
  // run Electron upgrade checks, eg 7..8 to check an upgrade from Electron 7 to 8 (optional)
  electronUpgrade: '7..8',
  // assume the set Electron version, overriding the detected one (optional)
  electronVersionOverride: '28.0.0',
  // skip the checks that need network access (optional)
  offline: true,
  // don't report findings accepted in a baseline file (optional)
  baseline: '.electronegativity-baseline.json',
  // also scan tests, fixtures, vendored and minified files (optional)
  allFiles: false,
  // use additional Babel parser plugins (optional)
  parserPlugins: ['doExpressions']
})
    .then(result => console.log(result))
    .catch(err => console.error(err));
```

The result contains the number of global and atomic checks that ran, the files that could not be parsed, every finding (`issues`), the findings left after applying the baseline (`reported`), the ones the baseline accepted (`suppressed`) and baseline entries that no longer match anything (`staleBaselineEntries`):

```js
{
  globalChecks: 14,
  atomicChecks: 72,
  errors: [],
  issues: [
    {
      file: 'src/main.js',
      sample: "win.webContents.on('will-navigate', (event, url) => console.log('navigating to', url));",
      location: { line: 20, column: 2 },
      id: 'LIMIT_NAVIGATION_JS_CHECK',
      description: 'Evaluate the implementation of the navigation limits (will-navigate, will-frame-navigate, setWindowOpenHandler): the will-navigate handler never calls event.preventDefault(), so it blocks nothing',
      properties: { event: 'will-navigate-noop' },
      severity: { value: 3, name: 'HIGH' },
      confidence: { value: 2, name: 'CERTAIN' },
      manualReview: false,
      shortenedURL: 'https://www.electronjs.org/docs/latest/tutorial/security#13-disable-or-limit-navigation'
    },
    // ...
  ],
  reported: [ /* ... */ ],
  suppressed: [],
  staleBaselineEntries: []
}
```

Each finding's `shortenedURL` points to the documentation of the problem: the matching section of the [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security) or API docs where there is one, otherwise MDN, OWASP, Node.js or OSV.

## Contributing

If you're thinking about contributing to this project, please take a look at our [CONTRIBUTING.md](https://github.com/doyensec/electronegativity/blob/master/CONTRIBUTING.md).

## Credits

Electronegativity was made possible thanks to the work of many [contributors](https://github.com/doyensec/electronegativity/graphs/contributors).

This project has been sponsored by [Doyensec LLC](https://www.doyensec.com). 

![Doyensec Research](https://github.com/doyensec/inql/blob/master/docs/doyensec_logo.svg "Doyensec Logo")

[Engage us to break](https://doyensec.com/auditing.html) your Electron.js application!
