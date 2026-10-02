<!-- Electronegativity tester notes: not part of the client report -->

# Privileged Functionality Exposed to Web Content: tester notes

Working notes for the finding `Privileged Functionality Exposed to Web Content.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Likely.

- Rating basis: CONTEXT_BRIDGE_EXPOSURE_JS_CHECK at src/preload.js:2; scanner severity HIGH, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 1 instance requires reachability or configuration review; exploitation has not been established for those instances.

## Checks

- **CONTEXT_BRIDGE_EXPOSURE_JS_CHECK** (1 instance): The preload exposes powerful APIs (e.g. raw ipcRenderer) to the page: any script injected into the page (XSS) can use them.

## Scenarios

- **Broad preload bridge** (client label: Privileged functionality exposed by the preload script): 1 instance

## Validation steps

- **How to confirm (Broad preload bridge):** List exposed methods, origins and their main-process handlers; verify the origin of a live caller.

## Recorded evidence (all instances)

- **CONTEXT_BRIDGE_EXPOSURE_JS_CHECK** at `src/preload.js:2`
  - Validation: not run; static or artifact observation only
  - Source column: 39
  - Description: Powerful Electron/Node.js APIs are exposed to the renderer through contextBridge (exposes ipcRenderer)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 1 instance by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
