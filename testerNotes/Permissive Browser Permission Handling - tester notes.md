<!-- Electronegativity tester notes: not part of the client report -->

# Permissive Browser Permission Handling: tester notes

Working notes for the finding `Permissive Browser Permission Handling.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Possible.

- Rating basis: PERMISSION_REQUEST_HANDLER_JS_CHECK at src/main.js:15; scanner severity HIGH, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **PERMISSION_REQUEST_HANDLER_JS_CHECK** (1 instance): Without a permission handler, any page (including one reached through a link in shared content) gets camera, microphone, notifications and other permissions automatically.

## Scenarios

- **Permission request callback** (client label: Permission requests granted without restriction): 1 instance

## Validation steps

- **How to confirm (Permission request callback):** Request a benign permission from the affected origin and record the handler and decision.
- **PERMISSION_REQUEST_HANDLER_JS_CHECK:** Automatic: a watch session records the permissions pages were granted.

## Recorded evidence (all instances)

- **PERMISSION_REQUEST_HANDLER_JS_CHECK** at `src/main.js:15`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: Permission handler: setPermissionRequestHandler grants every permission to every origin

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Confirm that a user really does what this finding needs them to do (for example, click a link or open a document). How: [Confirm what the user has to do](How%20to%20Prepare%20Findings%20for%20Release.md#confirm-what-the-user-has-to-do).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
