<!-- Electronegativity tester notes: not part of the client report -->

# Debugging Features Enabled in Production: tester notes

Working notes for the finding `Debugging Features Enabled in Production.md`. They are not part of the client report.

## Rating basis

Consequence: Low. Likelihood: Unlikely.

- Rating basis: DEVTOOLS_JS_CHECK at src/main.js:13; scanner severity MEDIUM, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **DEVTOOLS_JS_CHECK** (1 instance): DevTools can be opened in the shipped app: someone at the keyboard can inspect and run code in the app's context. Other users' content cannot use this.

## Scenarios

- **Developer tooling or test hooks** (client label: Developer tools or test functions available): 1 instance

## Validation steps

- **How to confirm (Developer tooling or test hooks):** Inspect the packaged build and exercise only the documented development entry point.
- **DEVTOOLS_JS_CHECK:** Manual, local access only: in the installed build, press Ctrl+Shift+I (or use the View menu) and check whether DevTools open; they don't when the call is behind a development flag. Content from other users cannot use it.

## Recorded evidence (all instances)

- **DEVTOOLS_JS_CHECK** at `src/main.js:13`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: DevTools are opened programmatically; ensure this cannot happen in production builds (always opened, including in production builds)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
