<!-- Electronegativity tester notes: not part of the client report -->

# Insufficient Navigation and New Window Restrictions: tester notes

Working notes for the finding `Insufficient Navigation and New Window Restrictions.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Possible.

- Rating basis: LIMIT_NAVIGATION_JS_CHECK at src/main.js:20; scanner severity HIGH, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.
- 1 instance requires reachability or configuration review; exploitation has not been established for those instances.

## Checks

- **LIMIT_NAVIGATION_JS_CHECK** (1 instance): Windows can be navigated to any site (e.g. by a link in shared content); that site then runs inside the app window, with its preload and IPC access.
- **LIMIT_NAVIGATION_GLOBAL_CHECK** (1 instance): Windows can be navigated to any site (e.g. by a link in shared content); that site then runs inside the app window, with its preload and IPC access.
- **WEBVIEW_GLOBAL_CHECK** (1 instance): A \<webview\> embeds other content; misconfigured, that content runs with Node.js or preload access.
- **WINDOW_OPEN_HANDLER_JS_CHECK** (1 instance): window.open() and target=_blank links in page content open app windows the app does not vet (phishing, getting around navigation limits).
- **WEBVIEW_TAG_JS_CHECK** (1 instance): The \<webview\> tag is enabled: script injected into the page can create webviews with its own settings.
- **ALLOWPOPUPS_HTML_CHECK** (1 instance): The content shown in this \<webview\> can open new windows, e.g. for phishing or to get around navigation limits.

## Scenarios

- **Top-level navigation or redirect** (client label: Navigation and redirects not restricted): 2 instances
- **Popup or middle-click** (client label: New windows not restricted): 2 instances
- **Embedded content** (client label: Embedded content not restricted): 2 instances

## Validation steps

- **How to confirm (Top-level navigation or redirect):** Exercise a benign external link and redirect while recording the final URL and window settings.
- **How to confirm (Popup or middle-click):** Test a benign popup and middle-click in the affected renderer and inspect its options.
- **How to confirm (Embedded content):** Inspect webview attachment and iframe sandbox attributes for the actual loaded source.
- **LIMIT_NAVIGATION_JS_CHECK:** Automatic: in a watch session, put the link https://example.invalid/<marker> the tool prints into shared content and click it (also Ctrl+click and middle-click). The report shows whether the app navigated, opened a window, handed it to the OS, or blocked it.
- **LIMIT_NAVIGATION_GLOBAL_CHECK:** Automatic: in a watch session, put the link https://example.invalid/<marker> the tool prints into shared content and click it (also Ctrl+click and middle-click). The report shows whether the app navigated, opened a window, handed it to the OS, or blocked it.
- **WINDOW_OPEN_HANDLER_JS_CHECK:** Automatic: in a watch session, put the link https://example.invalid/<marker> the tool prints into shared content and click it (also Ctrl+click and middle-click). The report shows whether the app navigated, opened a window, handed it to the OS, or blocked it.

## Recorded evidence (all instances)

- **LIMIT_NAVIGATION_JS_CHECK** at `src/main.js:20`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: Evaluate the implementation of the navigation limits (will-navigate, will-frame-navigate, setWindowOpenHandler): the will-navigate handler never calls event.preventDefault(), so it blocks nothing
- **LIMIT_NAVIGATION_GLOBAL_CHECK** at vulnerable-app (application-wide)
  - Validation: not run; static or artifact observation only
  - Description: Missing will-navigate navigation limit
- **WEBVIEW_GLOBAL_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 106
  - Description: The \<webview\> tag is enabled but no will-attach-webview handler verifies webview options before creation
- **WINDOW_OPEN_HANDLER_JS_CHECK** at `src/main.js:23`
  - Validation: not run; static or artifact observation only
  - Source column: 11
  - Description: setWindowOpenHandler allows new windows to be created; verify that only trusted URLs are allowed (every URL is allowed to open a new window)
- **WEBVIEW_TAG_JS_CHECK** at `src/main.js:10`
  - Validation: not run; static or artifact observation only
  - Source column: 106
  - Description: The \<webview\> tag is enabled
- **ALLOWPOPUPS_HTML_CHECK** at `src/index.html:1`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: Do not allow popups in webview

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Review 1 instance by hand (flagged for manual review, or found with tentative confidence). How: [Review an instance by hand](How%20to%20Prepare%20Findings%20for%20Release.md#review-an-instance-by-hand).
- [ ] Confirm that a user really does what this finding needs them to do (for example, click a link or open a document). How: [Confirm what the user has to do](How%20to%20Prepare%20Findings%20for%20Release.md#confirm-what-the-user-has-to-do).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
