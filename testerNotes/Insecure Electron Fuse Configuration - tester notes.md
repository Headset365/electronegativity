<!-- Electronegativity tester notes: not part of the client report -->

# Insecure Electron Fuse Configuration: tester notes

Working notes for the finding `Insecure Electron Fuse Configuration.md`. They are not part of the client report.

## Rating basis

Consequence: Low. Likelihood: Rare.

- Rating basis: FUSES_GLOBAL_CHECK at package.json:1; scanner severity MEDIUM, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **FUSES_GLOBAL_CHECK** (1 instance): Build hardening left at insecure defaults. It matters to someone who can start or modify the app on the device (e.g. RunAsNode turns it into a Node.js interpreter), not to other users' content.

## Scenarios

- **Local Node entry points** (client label: Node.js entry points enabled): 1 instance
- **Asar integrity and loading** (client label: Archive integrity not enforced): 1 instance
- **Cookie or file-protocol privileges** (client label: Cookie encryption or file protocol fuse insecure): 1 instance

## Validation steps

- **How to confirm (Local Node entry points):** Read the packaged fuse values and compare them with the build configuration.
- **How to confirm (Asar integrity and loading):** Check both fuse values and the executable’s embedded integrity digest.
- **How to confirm (Cookie or file-protocol privileges):** Inspect the relevant fuse and confirm actual cookie storage and file URL use.
- **FUSES_GLOBAL_CHECK:** Manual, local access only: set the fuses in the build (@electron/fuses). Content from other users cannot use them.
- **Validation command:** `npx @electron/fuses read --app "<exe>"`

## Recorded evidence (all instances)

- **FUSES_GLOBAL_CHECK** at `package.json:1`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: No Electron Fuses configuration found. RunAsNode, NODE_OPTIONS, --inspect and ASAR integrity fuses are insecure by default (electron-builder)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
