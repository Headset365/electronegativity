<!-- Electronegativity tester notes: not part of the client report -->

# Cross-Site Scripting in Content Rendering: tester notes

Working notes for the finding `Cross-Site Scripting in Content Rendering.md`. They are not part of the client report.

## Rating basis

Consequence: Medium. Likelihood: Possible.

- Rating basis: XSS_SINK_JS_CHECK at src/preload.js:3; scanner severity MEDIUM, confidence FIRM; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 1 instance requires reachability or configuration review; exploitation has not been established for those instances.

## Checks

- **XSS_SINK_JS_CHECK** (1 instance): Dynamic data is inserted as HTML: if it can hold content stored by another user, their markup runs as script in this window (XSS).

## Scenarios

- **HTML sink or editor** (client label: Dynamic content inserted as HTML): 1 instance

1 instance was not validated at runtime, or had an inconclusive result, and is not listed under Reproduction and Evidence in the client finding.

## Validation steps

- **How to confirm (HTML sink or editor):** Follow a harmless unique marker from its input to the rendered sink; distinguish text from live HTML and script execution.
- **XSS_SINK_JS_CHECK:** Automatic: in a watch session (electronegativity --app <install folder>), save content carrying the HTML marker the tool prints, in the fields this code shows, then view it. If the markup reaches this code, the finding is confirmed at this location.

## Recorded evidence (all instances)

- **XSS_SINK_JS_CHECK** at `src/preload.js:3`
  - Validation: not run; static or artifact observation only
  - Source column: 28
  - sink: innerHTML
  - Description: HTML is built from dynamic data; unsanitised input leads to XSS in the renderer (innerHTML with a dynamic value)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 1 instance by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Decide what to do about 1 instance left out of Reproduction and Evidence because it was not validated. How: [Decide about instances not validated](How%20to%20Prepare%20Findings%20for%20Release.md#decide-about-instances-not-validated).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
