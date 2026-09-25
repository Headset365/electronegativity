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
* 80 security checks (up from 42), covering the current [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security): IPC sender validation, APIs exposed through `contextBridge`, Electron Fuses, `setWindowOpenHandler`, `<webview>` hardening, custom scheme privileges, disabled TLS validation, `shell` APIs, deep link and file association handlers, DevTools, Secure Keyboard Entry, WebGL/WebSQL and certificate pinning.
* Outdated software: end-of-life Electron majors, newer patch releases of pinned versions, and known vulnerabilities in every locked npm dependency.
* Findings follow the Electron version in use, e.g. `affinity` is ignored from Electron 14 and the `new-window` event is reported as ineffective from Electron 22.
* Upgrade checks (`-u`) for the breaking changes of Electron 12 to 32.
* A self-contained, filterable HTML report (`-o report.html`) and JSON output, next to CSV and SARIF.

## Checks

Checks run on JavaScript/TypeScript, HTML, `package.json`/`electron-builder.json` and lockfiles. Global checks combine the findings of several files, e.g. to report a protection that is missing from the whole application.

| Area | Checks |
|---|---|
| Renderer isolation | `NODE_INTEGRATION_*`, `CONTEXT_ISOLATION_JS_CHECK`, `SANDBOX_*` (incl. `app.enableSandbox()`), `PRELOAD_JS_CHECK`, `REMOTE_MODULE_JS_CHECK` (incl. `@electron/remote`), `AFFINITY_*` |
| IPC and preload | `IPC_SENDER_VALIDATION_JS_CHECK`, `CONTEXT_BRIDGE_EXPOSURE_JS_CHECK` |
| Binary hardening | `FUSES_JS_CHECK`, `FUSES_JSON_CHECK`, `FUSES_GLOBAL_CHECK` (RunAsNode, NODE_OPTIONS, `--inspect`, ASAR integrity, cookie encryption, ...) |
| Web security | `WEB_SECURITY_*`, `INSECURE_CONTENT_*`, `HTTP_RESOURCES_*`, `CSP_*`, `EXPERIMENTAL_FEATURES_*`, `BLINK_FEATURES_*`, `WEBGL_*`, `WEBSQL_*`, `PLUGINS_*`, `NAVIGATE_ON_DRAG_DROP_*`, `XSS_SINK_JS_CHECK` |
| Navigation and windows | `LIMIT_NAVIGATION_*`, `WINDOW_OPEN_HANDLER_JS_CHECK`, `UNTRUSTED_LOAD_URL_JS_CHECK`, `FILE_PROTOCOL_JS_CHECK`, `AUXCLICK_*`, `ALLOWPOPUPS_HTML_CHECK`, `WEBVIEW_TAG_JS_CHECK`, `WEBVIEW_GLOBAL_CHECK` |
| Dangerous APIs | `DANGEROUS_FUNCTIONS_JS_CHECK`, `OPEN_EXTERNAL_JS_CHECK`, `OPEN_PATH_JS_CHECK`, `SHOWITEMINFOLDER_JS_CHECK`, `WRITE_SHORTCUT_JS_CHECK`, `COMMAND_INJECTION_JS_CHECK`, `DEVTOOLS_JS_CHECK` |
| Protocols and external input | `PROTOCOL_HANDLER_JS_CHECK`, `PROTOCOL_PRIVILEGES_JS_CHECK`, `FILE_HANDLER_JS_CHECK`, `FILE_HANDLER_JSON_CHECK`, `PERMISSION_REQUEST_HANDLER_*` |
| TLS | `CERTIFICATE_ERROR_EVENT_JS_CHECK`, `CERTIFICATE_VERIFY_PROC_JS_CHECK`, `CERTIFICATE_PINNING_GLOBAL_CHECK`, `NODE_TLS_REJECT_UNAUTHORIZED_*` |
| Configuration | `CUSTOM_ARGUMENTS_*`, `SECURITY_WARNINGS_DISABLED_*`, `SECUREKEYBOARDENTRY_*` |
| Outdated software | `ELECTRON_VERSION_JSON_CHECK`, `AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK`, `UNSUPPORTED_VERSION_GLOBAL_CHECK`, `DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK` |

The outdated software checks need network access: they query [releases.electronjs.org](https://releases.electronjs.org) (cached for 12 hours) and the [OSV](https://osv.dev) vulnerability database. Offline, they print a warning and are skipped; `--offline` skips them without trying.

### Confidence

Every finding has a confidence level:

* **CERTAIN**: the insecure setting or behavior is stated in the code, e.g. `webSecurity: false`, a permission handler that calls `callback(true)` unconditionally, or a `will-navigate` handler that never calls `event.preventDefault()`.
* **FIRM**: the code analysis shows the problem, but it depends on something that can't be fully proven statically, e.g. an `openExternal()` argument that flows from an IPC handler parameter, or a handler that only allows some URLs.
* **TENTATIVE**: the relevant value isn't known at all, e.g. a setting taken from a variable defined in another file.

Rather than flagging every use of a sensitive API, checks look at what the code does with it: they resolve constants, follow values from handler parameters through local variables, recognize URL validation (`new URL()`, origin/protocol checks, allowlists) and tell conditional code from unconditional code. A setting that is secure by default in the Electron version in use is not reported.

### Test coverage

`test/test_checklist.js` covers each item of the [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security) and the other practices above with an insecure example, which must be reported with the expected severity and confidence, and a secure one, which must not be. `test/apps` contains a hardened sample app, which must only produce low-severity "review the allowlist" notes, and a vulnerable one, which must trigger each check with a firm or certain confidence.

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

[Electronegativity Action](https://github.com/marketplace/actions/electronegativity) may run as part of your GitHub CI/CD pipeline to get "Code scanning alerts":

![Code scanning alerts](https://github.com/doyensec/electronegativity/raw/master/docs/resources/img/codescanningalerts.png "Code scanning alerts")

### Programmatically

You can also use electronegativity programmatically, using similar options as for the CLI. Add it to your project from GitHub first (the package keeps the name `@doyensec/electronegativity`):

```
$ npm install github:Headset365/electronegativity
```

```js
const run = require('@doyensec/electronegativity')
// or: import run from '@doyensec/electronegativity';

run({
  // input (directory, .js, .html, .asar)
  input: '/path/to/electron/app',
  // save the results to a file in csv or sarif format (optional)
  output: '/path/for/output/file',
  // true to save output as sarif, false to save as csv (optional)
  isSarif: false,
  // only run the specified checks (optional)
  customScan: ['dangerousfunctionsjscheck', 'remotemodulejscheck'],
  // only return findings with the specified level of severity or above (optional)
  severitySet: 'high',
  // only return findings with the specified level of confidence or above (optional)
  confidenceSet: 'certain',
  // show relative path for files (optional)
  isRelative: false,
  // run Electron upgrade checks, eg -u 7..8 to check upgrade from Electron 7 to 8 (optional)
  electronUpgrade: '7..8',
  // assume the set Electron version, overriding the detected one
  electronVersionOverride: '5.0.0',
  // use additional Babel parser plugins
  parserPlugins: ['doExpressions']
})
    .then(result => console.log(result))
    .catch(err => console.error(err));
```

The result contains the number of global and atomic checks, any errors encountered while parsing and an array of the issues found, like this:

```js
{
  globalChecks: 6,
  atomicChecks: 36,
  errors: [
    {
      file: 'ts/main/main.ts',
      sample: 'shell.openExternal(url);',
      location: { line: 328, column: 4 },
      id: 'OPEN_EXTERNAL_JS_CHECK',
      description: 'Review the use of openExternal',
      properties: undefined,
      severity: { value: 2, name: 'MEDIUM', format: [Function: format] },
      confidence: { value: 0, name: 'TENTATIVE', format: [Function: format] },
      manualReview: true,
      shortenedURL: 'https://git.io/JeuMC'
    },
    {
      file: 'ts/main/main.ts',
      sample: 'const popup = new BrowserWindow(options);',
      location: { line: 340, column: 18 },
      id: 'CONTEXT_ISOLATION_JS_CHECK',
      description: 'Review the use of the contextIsolation option',
      properties: undefined,
      severity: { value: 3, name: 'HIGH', format: [Function: format] },
      confidence: { value: 1, name: 'FIRM', format: [Function: format] },
      manualReview: false,
      shortenedURL: 'https://git.io/Jeu1p'
    }
  ]
}
```

## Contributing

If you're thinking about contributing to this project, please take a look at our [CONTRIBUTING.md](https://github.com/doyensec/electronegativity/blob/master/CONTRIBUTING.md).

## Credits

Electronegativity was made possible thanks to the work of many [contributors](https://github.com/doyensec/electronegativity/graphs/contributors).

This project has been sponsored by [Doyensec LLC](https://www.doyensec.com). 

![Doyensec Research](https://github.com/doyensec/inql/blob/master/docs/doyensec_logo.svg "Doyensec Logo")

[Engage us to break](https://doyensec.com/auditing.html) your Electron.js application!
