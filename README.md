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

### What's new in 2.0

* Supports modern Electron projects: `.mjs`/`.cjs`/`.mts`/`.cts` sources, current ECMAScript and TypeScript syntax, and Electron versions detected from `package-lock.json` (v1-v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` and `node_modules/electron`.
* Checks account for the secure defaults of newer Electron releases: `contextIsolation` (Electron 12+), `sandbox` (Electron 20+, unless `nodeIntegration` is enabled) and the removal of the `remote` module (Electron 14+). When the Electron version can't be detected, the oldest (least secure) defaults are still assumed.
* `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK` now queries the [OSV](https://osv.dev) database of published Electron security advisories (GitHub Security Advisories), as Electron's former release feed stopped being updated in 2022. Findings list the matching advisory IDs.
* Native ES modules with no build step, running on current versions of all dependencies (Babel 8, TypeScript ESTree 8, espree, eslint-scope, cheerio 1.x, commander, chalk).
* 95 security checks (up from 42), covering the current [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security): IPC sender validation, APIs exposed through `contextBridge`, Electron Fuses, `setWindowOpenHandler`, `<webview>` hardening, custom scheme privileges, disabled TLS validation, `shell` APIs, deep link and file association handlers, downloads, update feeds, plaintext secrets, screen capture, DevTools, Secure Keyboard Entry, WebGL/WebSQL, unsandboxed iframes, HTML injection into AngularJS and rich-text editors, AngularJS `$sce` configuration and certificate pinning.
* Outdated software: end-of-life Electron majors, newer patch releases of pinned versions, and known vulnerabilities in every locked npm dependency. Development-only packages are reported as LOW: npm lockfiles record them, and for Yarn and pnpm lockfiles they are worked out from the `dependencies` of the project's `package.json` files and workspaces.
* Findings follow the Electron version in use, e.g. `affinity` is ignored from Electron 14 and the `new-window` event is reported as ineffective from Electron 22.
* Upgrade checks (`-u`) for the breaking changes of Electron 12 to 32.
* A self-contained, filterable HTML report (`-o report.html`) and JSON output, next to CSV and SARIF. The HTML report opens with the renderer attack surface: every window with its effective `nodeIntegration`, `contextIsolation`, `sandbox` and `webSecurity` settings and what page script could reach in it, and the APIs each preload script exposes to web content.
* Cross-file analysis: handlers, helpers and constants imported from other files (ES modules, CommonJS, re-exports, `tsconfig.json` `baseUrl`/`paths` aliases) and handler factories are followed. Window options merged from shared defaults (`{ ...defaults }`, `Object.assign({}, defaults, options)`, `Object.freeze(...)`, also across files) and data from IPC, navigation and deep link handlers is followed into the helpers it is passed to, across files and up to six calls deep. A helper parameter that every caller in the project sets to a constant is reported as LOW. Minified bundles (`new o.BrowserWindow(...)`, `!0`/`!1`) are understood, and inline `<script>` blocks of HTML files go through the JavaScript checks.
* Baselines (`--baseline`, `--write-baseline`) and a CI exit code (`--fail-on`), see [CI](#cicd).
* Tests, fixtures, vendored code, tooling folders (`scripts`, `tools`, dot-folders) and minified files are skipped by default (`--all-files` to include them). Vendored code includes bower and jspm folders (`.bowerrc`) and copied libraries, recognized by a header comment naming the file with a version and license (e.g. `js/jquery.js`).
* Validated on Signal Desktop, Element, VS Code, Mattermost, GitHub Desktop, Hyper and Electron Fiddle: no parse errors, and the remaining HIGH findings were confirmed by hand. Cross-checked against old releases with published vulnerabilities, see [Known vulnerabilities](#known-vulnerabilities).

## Checks

Checks run on JavaScript/TypeScript, HTML, `package.json`/`electron-builder.json` and lockfiles. Global checks combine the findings of several files, e.g. to report a protection that is missing from the whole application.

| Area | Checks |
|---|---|
| Renderer isolation | `NODE_INTEGRATION_*`, `CONTEXT_ISOLATION_JS_CHECK`, `SANDBOX_*` (incl. `app.enableSandbox()`), `PRELOAD_JS_CHECK`, `REMOTE_MODULE_JS_CHECK` (incl. `@electron/remote`), `AFFINITY_*` |
| IPC and preload | `IPC_SENDER_VALIDATION_JS_CHECK`, `CONTEXT_BRIDGE_EXPOSURE_JS_CHECK` |
| Binary hardening | `FUSES_JS_CHECK`, `FUSES_JSON_CHECK`, `FUSES_GLOBAL_CHECK` (RunAsNode, NODE_OPTIONS, `--inspect`, ASAR integrity, cookie encryption, ...) |
| Web security | `WEB_SECURITY_*`, `INSECURE_CONTENT_*`, `HTTP_RESOURCES_*`, `CSP_*`, `EXPERIMENTAL_FEATURES_*`, `BLINK_FEATURES_*`, `WEBGL_*`, `WEBSQL_*`, `PLUGINS_*`, `NAVIGATE_ON_DRAG_DROP_*`, `XSS_SINK_JS_CHECK` (DOM, React and jQuery sinks; server-fed HTML raised to HIGH), `RICH_TEXT_EDITOR_JS_CHECK`, `ANGULAR_TRUST_HTML_JS_CHECK`, `ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK`, `IFRAME_SANDBOX_*`, `ANGULAR_SCE_DISABLED_JS_CHECK`, `ANGULAR_RESOURCE_URL_LIST_JS_CHECK` |
| Navigation and windows | `LIMIT_NAVIGATION_*`, `WINDOW_OPEN_HANDLER_JS_CHECK`, `UNTRUSTED_LOAD_URL_JS_CHECK`, `FILE_PROTOCOL_JS_CHECK`, `AUXCLICK_*`, `ALLOWPOPUPS_HTML_CHECK`, `WEBVIEW_TAG_JS_CHECK`, `WEBVIEW_GLOBAL_CHECK` |
| Dangerous APIs | `DANGEROUS_FUNCTIONS_JS_CHECK`, `OPEN_EXTERNAL_JS_CHECK`, `OPEN_PATH_JS_CHECK`, `SHOWITEMINFOLDER_JS_CHECK`, `WRITE_SHORTCUT_JS_CHECK`, `COMMAND_INJECTION_JS_CHECK`, `DEVTOOLS_JS_CHECK` |
| Protocols and external input | `PROTOCOL_HANDLER_JS_CHECK`, `PROTOCOL_PRIVILEGES_JS_CHECK`, `FILE_HANDLER_JS_CHECK`, `FILE_HANDLER_JSON_CHECK`, `PERMISSION_REQUEST_HANDLER_*` |
| TLS | `CERTIFICATE_ERROR_EVENT_JS_CHECK`, `CERTIFICATE_VERIFY_PROC_JS_CHECK`, `CERTIFICATE_PINNING_GLOBAL_CHECK`, `NODE_TLS_REJECT_UNAUTHORIZED_*` |
| Configuration | `CUSTOM_ARGUMENTS_*`, `SECURITY_WARNINGS_DISABLED_*`, `SECUREKEYBOARDENTRY_*`, `PLAINTEXT_SECRETS_JS_CHECK` |
| Downloads and updates | `DOWNLOAD_JS_CHECK` (auto-opened downloads, server-chosen file names), `UPDATE_SECURITY_*` (HTTP feeds, unverified signatures, downgrades) |
| Outdated software | `ELECTRON_VERSION_JSON_CHECK`, `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK`, `UNSUPPORTED_VERSION_GLOBAL_CHECK`, `DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK` (also for library copies bundled with the app), `END_OF_LIFE_LIBRARY_GLOBAL_CHECK` (AngularJS, jQuery 1.x/2.x, Bootstrap 2-4; works offline) |
| Attack surface inventory | `WINDOW_SUMMARY_JS_CHECK`, `EXPOSED_API_JS_CHECK` (informational, shown as tables in the HTML report) |
| Runtime (`--watch`) | `RUNTIME_NODE_INTEGRATION`, `RUNTIME_CONTEXT_ISOLATION`, `RUNTIME_SANDBOX`, `RUNTIME_WEB_SECURITY`, `RUNTIME_CSP`, `RUNTIME_INSECURE_LOAD`, `RUNTIME_NAVIGATION`, `RUNTIME_NEW_WINDOW`, `RUNTIME_WEBVIEW`, `RUNTIME_OPEN_EXTERNAL`, `RUNTIME_OPEN_PATH`, `RUNTIME_PERMISSION`, `RUNTIME_PERMISSION_CHECK`, `RUNTIME_CERTIFICATE_ERROR`, `RUNTIME_DOM_INJECTION`, `RUNTIME_MARKER`, `RUNTIME_IPC`, `RUNTIME_COVERAGE`, `RUNTIME_WINDOW_COVERAGE`, `PACKAGED_FUSES` |

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
| -i, --input  | input (directory, .js, .html, .asar)               |
| -l, --checks | only run the specified checks, passed in csv format |
| -x, --exclude-checks <excludedCheckNames> | skip the specified checks list, passed in csv format |
| -s, --severity | only return findings with the specified level of severity or above |
| -c, --confidence | only return findings with the specified level of confidence or above |
| -o, --output <filename> | save the results to a file: `.html` report, `.json`, `.sarif` or `.csv`. The `-s` and `-c` thresholds apply |
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
| -h, --help   | output usage information                          |


Using electronegativity to look for issues in a directory containing an Electron app:
```
$ electronegativity -i /path/to/electron/app
```

Using electronegativity to look for issues in an `asar` archive and saving the results in an HTML report:
```
$ electronegativity -i /path/to/asar/archive -o report.html
```

The HTML report is a single file with no external resources. It summarizes the findings by severity and check, and can be filtered by severity, confidence, check, manual review status and free text.

Using electronegativity when upgrading from one version of Electron to another to find breaking changes:
```
$ electronegativity -i /path/to/electron/app -v -u 22..32
```

Note: if you're running into the Fatal Error "JavaScript heap out of memory", you can run node using ```node --max-old-space-size=4096 electronegativity -i /path/to/asar/archive -o result.csv```

### Watch mode (runtime observation)

Static analysis reads all the code, including the parts behind a login. Watch mode adds what actually happens when the app runs: settings computed at runtime, the Content Security Policy each page really gets, and which IPC channels your session exercised.

```
$ electronegativity --watch ./my-app -o report.html          # app folder with Electron installed
$ electronegativity --watch ./dist/linux-unpacked/my-app -o report.html   # packaged executable
$ electronegativity --watch ./my-app --watch-marker ENG42 -o report.html  # detect stored-content injection
$ electronegativity --watch-log session.jsonl -i ./my-app -o report.html  # re-analyze an earlier session
```

The app starts with a small observer loaded into its main process, and a read-only script installed in each page. Log in and go through the features you want covered, then close the app. The report then includes:

* every page each window showed, with the `nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity` values and the preload script it ran with, linked to where the window is defined in the code;
* pages shown without a Content Security Policy (header or `<meta>`), or with one allowing inline scripts or `eval`;
* content loaded over plain http, navigation to other origins, new windows and `<webview>`s created for web content;
* `shell.openExternal` calls with non-web URLs and `shell.openPath` on executable file types;
* permissions granted automatically because the app has no permission request or check handler, and certificate errors;
* what the renderer-side observer saw inside pages: script inserted into the DOM at runtime (`on*` handlers, `javascript:` URLs) and, with `--watch-marker`, whether a planted marker came back as live HTML (the stored-content threat);
* for a packaged app, the Electron Fuses read from the shipped binary, not only from the build configuration;
* coverage: the IPC channels and the windows the app has that the session never exercised, and findings confirmed both in the code and at runtime.

To detect stored-content injection with `--watch-marker <token>`, put content carrying the token into the app from one account and open it as another user. The observer reports the token as live HTML when it became part of the page's markup (a tag or attribute name, or an event handler), and as shown safely when it only appears as text or in an ordinary attribute value such as a form field's value.

The observer only records: it doesn't change what the app does. URLs are stored without their query strings, and IPC arguments only by type. It is loaded through `NODE_OPTIONS`, which packaged apps ignore when the `EnableNodeOptionsEnvironmentVariable` fuse is off (as recommended for production): run watch mode on a development or test build. With an app folder, the folder is also scanned statically; with a packaged executable, its `resources/app.asar`.

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

The SARIF upload shows the findings as GitHub code scanning alerts.

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
