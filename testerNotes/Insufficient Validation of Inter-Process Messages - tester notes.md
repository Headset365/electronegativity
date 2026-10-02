<!-- Electronegativity tester notes: not part of the client report -->

# Insufficient Validation of Inter-Process Messages: tester notes

Working notes for the finding `Insufficient Validation of Inter-Process Messages.md`. They are not part of the client report.

## Rating basis

Consequence: Medium. Likelihood: Possible.

- Rating basis: IPC_SENDER_VALIDATION_JS_CHECK at src/main.js:26; scanner severity MEDIUM, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 4 instances require reachability or configuration review; exploitation has not been established for those instances.
- Channel-use conclusions depend on the shipped renderer and representative runtime coverage.

## Checks

- **IPC_SENDER_VALIDATION_JS_CHECK** (2 instances): The IPC handler does not check which page sent the message: script injected into any window, or a foreign page the window navigated to, can call it with the app's privileges.
- **IPC_HANDLER_JS_CHECK** (2 instances): What a page can make the main process do through this channel: script injected into a window that can reach it inherits these capabilities.

## Scenarios

- **Sender not restricted** (client label: Message sender not validated): 2 instances
- **Arguments or file paths trusted** (client label: Message arguments not validated): 2 instances

## Validation steps

- **How to confirm (Sender not restricted):** Trace the channel to its handler and check event.senderFrame.url against a live sender.
- **How to confirm (Arguments or file paths trusted):** Inspect the handler body and exercise a benign out-of-scope argument in an authorised test.
- **IPC_SENDER_VALIDATION_JS_CHECK:** Manual: read the handler and check that it verifies event.senderFrame (its URL or origin) before acting. A watch session lists the origins that used each channel, and whether content carrying the marker reached it.

## Recorded evidence (all instances)

- **IPC_SENDER_VALIDATION_JS_CHECK** at `src/main.js:26`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: IPC handler does not appear to validate the sender (event.senderFrame) before acting on the message
- **IPC_HANDLER_JS_CHECK** at `src/main.js:26`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: IPC handler: 'run' uses processes with arguments from the page (command); no rejecting input guard was recognised by this analysis; operations: process at main.js:26; argument checks: command not-recognised
- **IPC_SENDER_VALIDATION_JS_CHECK** at `src/main.js:27`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: IPC handler does not appear to validate the sender (event.senderFrame) before acting on the message
- **IPC_HANDLER_JS_CHECK** at `src/main.js:27`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: IPC handler: 'open' uses shell with arguments from the page (file); no rejecting input guard was recognised by this analysis; operations: shell-openPath at main.js:27; argument checks: file not-recognised; path containment not recognised for file

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 4 instances by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
