<!-- Electronegativity tester notes: not part of the client report -->

# Insecure Handling of Deep Links and File Associations: tester notes

Working notes for the finding `Insecure Handling of Deep Links and File Associations.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Unlikely.

- Rating basis: PROTOCOL_HANDLER_JS_CHECK at src/main.js:18; scanner severity HIGH, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 1 instance requires reachability or configuration review; exploitation has not been established for those instances.

## Checks

- **PROTOCOL_HANDLER_JS_CHECK** (1 instance): A custom protocol serves files: crafted URLs in content may read files outside the app (path traversal).

## Scenarios

- **External handler input** (client label: Unvalidated deep link or file association input): 1 instance

## Validation steps

- **How to confirm (External handler input):** Inspect the registered command and follow a benign crafted link or file through the parser.

## Recorded evidence (all instances)

- **PROTOCOL_HANDLER_JS_CHECK** at `src/main.js:18`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: Review the use of custom protocol handlers (request-derived file paths have no relevant pre-operation containment guard; validate traversal and caller access)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 1 instance by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Confirm that a user really does what this finding needs them to do (for example, click a link or open a document). How: [Confirm what the user has to do](How%20to%20Prepare%20Findings%20for%20Release.md#confirm-what-the-user-has-to-do).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
