<!-- Electronegativity tester notes: not part of the client report -->

# Insufficient Renderer Process Isolation: tester notes

Working notes for the finding `Insufficient Renderer Process Isolation.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Likely.

- Rating basis: NODE_INTEGRATION_JS_CHECK at src/main.js:10; scanner severity HIGH, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 2 instances require reachability or configuration review; exploitation has not been established for those instances.

## Checks

- **NODE_INTEGRATION_JS_CHECK** (1 instance): Page script has full Node.js access: any XSS in this window is code execution on the user's machine.
- **CONTEXT_ISOLATION_JS_CHECK** (1 instance): Page script shares its JavaScript world with the preload: an XSS in this window can tamper with the preload and reach its privileged APIs, often up to Node.js.
- **HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK** (1 instance): Plain http content is loaded into a window with Node.js: someone on the network path gets code execution on the machine.
- **SANDBOX_JS_CHECK** (1 instance): The renderer is not sandboxed: page content exploiting a Chromium bug escapes to the operating system more easily.
- **PRELOAD_JS_CHECK** (1 instance): A preload script runs with extra privileges in each page: review what it exposes.

## Scenarios

- **Node access in a renderer** (client label: Node.js integration enabled): 2 instances
- **Isolation or sandbox disabled** (client label: Context isolation or sandbox disabled): 3 instances

## Validation steps

- **How to confirm (Node access in a renderer):** Identify the affected window and confirm whether untrusted pages, documents or messages can execute script there.
- **How to confirm (Isolation or sandbox disabled):** Compare the packaged webPreferences with runtime window settings and the origin loaded in each window.
- **NODE_INTEGRATION_JS_CHECK:** Automatic: a watch session reports the settings each window really ran with.
- **CONTEXT_ISOLATION_JS_CHECK:** Automatic: a watch session reports the settings each window really ran with.
- **SANDBOX_JS_CHECK:** Automatic: a watch session reports the settings each window really ran with.

## Recorded evidence (all instances)

- **NODE_INTEGRATION_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 22
  - Description: Disable nodeIntegration for untrusted origins (nodeIntegration is enabled)
- **CONTEXT_ISOLATION_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 45
  - Description: Review the use of the contextIsolation option (contextIsolation is disabled)
- **HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK** at vulnerable-app (application-wide)
  - Validation: not run; static or artifact observation only
  - Description: The nodeIntegration flag is enabled for the application, but some resources are loaded over an unencrypted connection.
- **SANDBOX_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 90
  - Description: Use sandbox for untrusted origins
- **PRELOAD_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 124
  - Description: Review the use of preload scripts

### Supporting observations

- **WINDOW_SUMMARY_JS_CHECK** at `src/main.js:9`
  - Validation: not run; static or artifact observation only
  - Source column: 14
  - preload: preload.js
  - partition: default
  - nodeIntegration: true (explicit)
  - contextIsolation: false (explicit)
  - sandbox: false (explicit)
  - webSecurity: false (explicit)
  - nodeIntegrationInSubFrames: false (default)
  - webviewTag: true (explicit)
  - allowRunningInsecureContent: false (default)
  - Load target (loadURL): http://example.com
  - Description: Window security settings: BrowserWindow (nodeIntegration on, contextIsolation off, sandbox off, webSecurity off, preload preload.js)
- **EXPOSED_API_JS_CHECK** at `src/preload.js:2`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: API exposed to web content: window.ipc (value that can't be listed statically)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 2 instances by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
