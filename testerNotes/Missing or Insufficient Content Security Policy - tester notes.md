<!-- Electronegativity tester notes: not part of the client report -->

# Missing or Insufficient Content Security Policy: tester notes

Working notes for the finding `Missing or Insufficient Content Security Policy.md`. They are not part of the client report.

## Rating basis

Consequence: Medium. Likelihood: Likely.

- Rating basis: CSP_GLOBAL_CHECK at no single location; scanner severity MEDIUM, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **CSP_GLOBAL_CHECK** (1 instance): Without a Content Security Policy, injected markup can run inline script. A strict CSP is what turns an HTML injection into a harmless one.

## Scenarios

- **No effective policy** (client label: No Content Security Policy): 1 instance

## Validation steps

- **How to confirm (No effective policy):** Check the live response headers and meta elements for an enforceable policy, including redirects and frames.
- **CSP_GLOBAL_CHECK:** Automatic: a watch session records the Content Security Policy each page actually got.

## Recorded evidence (all instances)

- **CSP_GLOBAL_CHECK** at vulnerable-app (application-wide)
  - Validation: not run; static or artifact observation only
  - Description: No CSP has been detected in the target application

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
