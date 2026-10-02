<!-- Electronegativity tester notes: not part of the client report -->

# Browser Security Controls Disabled: tester notes

Working notes for the finding `Browser Security Controls Disabled.md`. They are not part of the client report.

## Rating basis

Consequence: Medium. Likelihood: Likely.

- Rating basis: WEB_SECURITY_JS_CHECK at src/main.js:10; scanner severity MEDIUM, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **WEB_SECURITY_JS_CHECK** (1 instance): The same-origin policy is off: script in the page can read data from any site and local files.

## Scenarios

- **Origin or transport protections** (client label: Browser security protections disabled): 1 instance

## Validation steps

- **How to confirm (Origin or transport protections):** Inspect the command-line switches and effective window settings; confirm the affected origin and resource.
- **WEB_SECURITY_JS_CHECK:** Automatic: a watch session reports the settings each window really ran with.

## Recorded evidence (all instances)

- **WEB_SECURITY_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 70
  - Description: Do not use disablewebsecurity

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
