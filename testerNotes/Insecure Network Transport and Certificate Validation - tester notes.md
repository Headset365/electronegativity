<!-- Electronegativity tester notes: not part of the client report -->

# Insecure Network Transport and Certificate Validation: tester notes

Working notes for the finding `Insecure Network Transport and Certificate Validation.md`. They are not part of the client report.

## Rating basis

Consequence: High. Likelihood: Likely.

- Rating basis: CERTIFICATE_VERIFY_PROC_JS_CHECK at src/main.js:16; scanner severity HIGH, confidence CERTAIN; runtime exploitability not established.
- The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.

## Checks

- **CERTIFICATE_VERIFY_PROC_JS_CHECK** (1 instance): Certificate verification is overridden: someone on the network can impersonate the server if the check is too lenient.
- **CUSTOM_ARGUMENTS_JS_CHECK** (1 instance): Chromium switches that weaken security (e.g. disabling web security or certificate checks) apply to all content the app shows.
- **CERTIFICATE_ERROR_EVENT_JS_CHECK** (1 instance): Invalid TLS certificates are accepted: someone on the network can impersonate the server and inject content.
- **HTTP_RESOURCES_HTML_CHECK** (1 instance): Content loaded over plain http can be modified by anyone on the network path (Wi-Fi, proxy).
- **HTTP_RESOURCES_JS_CHECK** (1 instance): Content loaded over plain http can be modified by anyone on the network path (Wi-Fi, proxy).
- **NODE_TLS_REJECT_UNAUTHORIZED_JSON_CHECK** (1 instance): TLS certificate checks are off for Node.js requests: someone on the network can impersonate the servers the app talks to.

## Scenarios

- **Cleartext HTTP or WebSocket** (client label: Unencrypted connections): 2 instances
- **Certificate validation bypass** (client label: Certificate validation disabled): 4 instances

## Validation steps

- **How to confirm (Cleartext HTTP or WebSocket):** Confirm the final scheme and host in a capture or live load.
- **How to confirm (Certificate validation bypass):** Identify the exact session, host and callback result; distinguish a rejected error from an accepted one.

## Recorded evidence (all instances)

- **CERTIFICATE_VERIFY_PROC_JS_CHECK** at `src/main.js:16`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: Do not allow insecure connections, by explicitly opting-out from TLS validation or importing untrusted certificates (every certificate is accepted, TLS validation is disabled)
- **CUSTOM_ARGUMENTS_JS_CHECK** at `src/main.js:6`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: Review the use of custom command line arguments: --ignore-certificate-errors
- **CERTIFICATE_ERROR_EVENT_JS_CHECK** at `src/main.js:30`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: Do not allow insecure connections, by explicitly opting-out from TLS validation (every invalid certificate is accepted)
- **HTTP_RESOURCES_HTML_CHECK** at `src/index.html:1`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: Do not allow insecure HTTP connections (\<script\> http://cdn.example.com/app.js)
- **HTTP_RESOURCES_JS_CHECK** at `src/main.js:12`
  - Validation: not run; static or artifact observation only
  - Source column: 2
  - Description: Do not allow insecure HTTP connections
- **NODE_TLS_REJECT_UNAUTHORIZED_JSON_CHECK** at `package.json:4`
  - Validation: not run; static or artifact observation only
  - Source column: 0
  - Description: TLS certificate validation is disabled for Node.js connections (NODE_TLS_REJECT_UNAUTHORIZED=0 or rejectUnauthorized: false) (in the npm script "start": it applies when the app is started with that script, typically in development; a packaged build does not run npm scripts)

## Before release

Do these before the finding goes to the client, and tick each one when it is done.

- [ ] Read the whole finding from top to bottom and remove anything that is not true for this application. How: [Read the finding](How%20to%20Prepare%20Findings%20for%20Release.md#read-the-finding).
- [ ] Check that the Consequence and Likelihood still fit after the checks above. How: [Check the rating](How%20to%20Prepare%20Findings%20for%20Release.md#check-the-rating).
