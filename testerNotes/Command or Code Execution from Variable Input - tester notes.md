<!-- Electronegativity tester notes: not part of the client report -->

# Command or Code Execution from Variable Input: tester notes

Working notes for the finding `Command or Code Execution from Variable Input.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Unlikely.

- Rating basis: COMMAND_INJECTION_JS_CHECK at src/main.js:26; scanner severity HIGH, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **COMMAND_INJECTION_JS_CHECK** (1 instance): Data from a page or an IPC message reaches a shell command: content that gets a message to it can run programs on the user's machine.

## Scenarios

- **Shell command construction** (client label: Operating system command built from variable input): 1 instance

## Validation steps

- **How to confirm (Shell command construction):** Trace the value to the process API; use a harmless marker to separate data flow from actual command execution.
- **COMMAND_INJECTION_JS_CHECK:** Automatic where a feature passes content on to a command: use the marker there during a watch session; the report says whether it reached a command line.

## Recorded evidence (all instances)

- **COMMAND_INJECTION_JS_CHECK** at `src/main.js:26`
  - Validation: not run; static or artifact observation only
  - Source column: 44
  - source: an IPC message from a renderer
  - Description: A child process is started with a dynamic command (exec receives data from an IPC message from a renderer)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Confirm that a user really does what this finding needs them to do (for example, click a link or open a document). How: [Confirm what the user has to do](How%20to%20Prepare%20Findings%20for%20Release.md#confirm-what-the-user-has-to-do).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
