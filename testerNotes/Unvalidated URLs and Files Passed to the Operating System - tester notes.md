<!-- Electronegativity tester notes: not part of the client report -->

# Unvalidated URLs and Files Passed to the Operating System: tester notes

Working notes for the finding `Unvalidated URLs and Files Passed to the Operating System.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Unlikely.

- Rating basis: OPEN_EXTERNAL_JS_CHECK at src/main.js:22; scanner severity HIGH, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **OPEN_EXTERNAL_JS_CHECK** (1 instance): A URL is handed to the operating system: if page content controls it, a crafted link (file:, smb:, a custom protocol) in shared content can launch programs or leak credentials.
- **OPEN_PATH_JS_CHECK** (1 instance): A path is opened with its default program: if page content or an IPC message controls it, it can run an executable or script on the machine.

## Scenarios

- **External URL or protocol** (client label: Unvalidated URLs opened by the operating system): 1 instance
- **Non-web protocol launch** (client label: Non-web protocols not blocked): 1 instance
- **Network-share credential exposure** (client label: Network share locations not blocked): 1 instance
- **File path handed to the host** (client label: Unvalidated file paths opened by the operating system): 1 instance
- **Executable file path** (client label: Executable files not blocked): 1 instance

## Validation steps

- **How to confirm (External URL or protocol):** Check which schemes and hosts reach openExternal; distinguish a recorded hand-off from attacker control.
- **How to confirm (Non-web protocol launch):** Test a benign custom-protocol or file URL and record whether the app blocks it before the OS hand-off.
- **How to confirm (Network-share credential exposure):** Check whether an untrusted link can pass a network-share target; do not collect real credentials during validation.
- **How to confirm (File path handed to the host):** Trace path construction, base-directory containment and the final extension in a benign test.
- **How to confirm (Executable file path):** Use a harmless test file to verify the path and extension policy without running an untrusted executable.
- **OPEN_EXTERNAL_JS_CHECK:** Automatic: in a watch session, put the link https://example.invalid/<marker> in shared content and click it, then a file:/// link the tool suggests. The report shows whether content reaches openExternal and whether non-web schemes get through.
- **OPEN_PATH_JS_CHECK:** Automatic: in a watch session, attach and open the <marker>.txt file the tool writes (or any file whose name carries the marker). The report shows whether a path from content reaches shell.openPath.

## Recorded evidence (all instances)

- **OPEN_EXTERNAL_JS_CHECK** at `src/main.js:22`
  - Validation: not run; static or artifact observation only
  - Source column: 4
  - source: a window.open() call or link in web content
  - Description: Review the use of openExternal (the value comes from a window.open() call or link in web content and is not validated)
- **OPEN_PATH_JS_CHECK** at `src/main.js:27`
  - Validation: not run; static or artifact observation only
  - Source column: 38
  - source: an IPC message from a renderer
  - Description: Review the use of shell.openPath with non-constant paths: opening attacker-influenced paths can execute files (the value comes from an IPC message from a renderer and is not validated)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Confirm that a user really does what this finding needs them to do (for example, click a link or open a document). How: [Confirm what the user has to do](How%20to%20Prepare%20Findings%20for%20Release.md#confirm-what-the-user-has-to-do).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
