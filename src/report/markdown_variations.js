// Alternatives for each client finding. A variant is shown when its checks occur; several variants may match one check.
// The client wording of each scenario is in markdown_client_copy.js.
// [scenario label, check ID pattern, how to distinguish this case, optional condition on the finding's own data]
// When several scenarios share a check, the condition picks the ones the finding's data supports; a finding whose data
// selects none of them gets the first scenario of its check.
import { CLIENT_COPY } from './markdown_client_copy.js';
import { validationResults } from '../finder/validation.js';

const describe = i => String(i.description || '');
const props = i => i.properties || {};
const executed = i => props(i).executed === true || props(i).execution === 'observed';
// the fuses a finding names: one fuse, the ones left unset, or none (no configuration found: every fuse at its default)
const fuses = names => i => {
  const named = props(i).fuse ? [props(i).fuse] : Array.isArray(props(i).unset) ? props(i).unset : undefined;
  return !named || named.some(name => names.includes(name));
};
// a CSP finding about a missing or unparsable policy rather than a weak one
const noPolicy = i => /\bno csp\b|not been detected|invalid/i.test(describe(i));
// the URL an openExternal finding opens: a constant or a URL seen at runtime; undefined when it comes from data
const target = i => [props(i).value, props(i).url, /^RUNTIME_/.test(i.id) ? i.file : undefined].find(v => typeof v === 'string' && v);
const validatedUrl = i => /validated first|every caller sets to a constant/i.test(describe(i));
const PUBLIC_SECRET = /google api key|publishable|public key/i;
const confidenceOf = i => i.confidence?.name || i.confidence;
export const VARIATIONS = {
  'Insufficient Renderer Process Isolation': [
    ['Node access in a renderer', /^(NODE_INTEGRATION|HTTP_RESOURCES_WITH_NODE_INTEGRATION|RUNTIME_NODE_INTEGRATION)/,
      'Identify the affected window and confirm whether untrusted pages, documents or messages can execute script there.'],
    ['Isolation or sandbox disabled', /^(CONTEXT_ISOLATION|SANDBOX|RUNTIME_CONTEXT_ISOLATION|RUNTIME_SANDBOX|PRELOAD)/,
      'Compare the packaged webPreferences with runtime window settings and the origin loaded in each window.'],
    ['Additional privilege sharing', /^(REMOTE_MODULE|AFFINITY)/,
      'Trace remote imports or affinity values to the windows that consume them.'],
    ['Injected script reached Node or Electron APIs', /^RUNTIME_CAMPAIGN_(NODE|ELECTRON|FS_READ)$/,
      'Match the campaign case, saved field and viewed page to the recorded signal, and check the window’s effective settings.'],
  ],
  'Browser Security Controls Disabled': [
    ['Origin or transport protections', /^(WEB_SECURITY|INSECURE_CONTENT|RUNTIME_WEB_SECURITY|CUSTOM_ARGUMENTS)/,
      'Inspect the command-line switches and effective window settings; confirm the affected origin and resource.'],
    ['Experimental or legacy capability', /^(EXPERIMENTAL_FEATURES|BLINK_FEATURES|WEBGL|WEBSQL|PLUGINS|NAVIGATE_ON_DRAG_DROP)/,
      'Check the runtime setting and determine whether the feature is needed by a production workflow.'],
    ['Warning or keyboard safeguard', /^(SECURITY_WARNINGS_DISABLED|SECUREKEYBOARDENTRY)/,
      'Inspect the packaged setting on the relevant operating system and reproduce the sensitive-input flow.'],
  ],
  'Privileged Functionality Exposed to Web Content': [
    ['Broad preload bridge', /^(CONTEXT_BRIDGE_EXPOSURE|RUNTIME_PRELOAD_FOREIGN_ORIGIN)/,
      'List exposed methods, origins and their main-process handlers; verify the origin of a live caller.'],
    ['Shared session between trust levels', /^(WINDOW_SESSION|RUNTIME_WINDOW_SESSION)/,
      'Compare partition identifiers and live origins for the affected windows.'],
  ],
  'Insufficient Validation of Inter-Process Messages': [
    ['Sender not restricted', /^(IPC_SENDER_VALIDATION|RUNTIME_MARKER_IPC)/,
      'Trace the channel to its handler and check event.senderFrame.url against a live sender.'],
    ['Arguments or file paths trusted', /^(IPC_HANDLER|IPC_FILE_ACCESS)/,
      'Inspect the handler body and exercise a benign out-of-scope argument in an authorised test.'],
    ['Unused or unexpected channel', /^IPC_CHANNEL_MAP/,
      'Compare registered channels with the shipped renderer and a representative watch session.'],
  ],
  'Unvalidated URLs and Files Passed to the Operating System': [
    ['External URL or protocol', /^(OPEN_EXTERNAL|RUNTIME_OPEN_EXTERNAL|RUNTIME_MARKER_OPEN_EXTERNAL)/,
      'Check which schemes and hosts reach openExternal; distinguish a recorded hand-off from attacker control.'],
    ['Non-web protocol launch', /^(OPEN_EXTERNAL|RUNTIME_OPEN_EXTERNAL|RUNTIME_MARKER_OPEN_EXTERNAL)/,
      'Test a benign custom-protocol or file URL and record whether the app blocks it before the OS hand-off.',
      i => target(i) ? !/^(https?|mailto):/i.test(target(i)) : !validatedUrl(i)],
    ['Network-share credential exposure', /^(OPEN_EXTERNAL|RUNTIME_OPEN_EXTERNAL|RUNTIME_MARKER_OPEN_EXTERNAL)/,
      'Check whether an untrusted link can pass a network-share target; do not collect real credentials during validation.',
      i => target(i) ? /^(\\\\|\/\/|file:|smb:)/i.test(target(i)) : !validatedUrl(i)],
    ['File path handed to the host', /^(OPEN_PATH|SHOWITEMINFOLDER|RUNTIME_OPEN_PATH|RUNTIME_MARKER_OPEN_PATH)/,
      'Trace path construction, base-directory containment and the final extension in a benign test.'],
    ['Executable file path', /^(OPEN_PATH|RUNTIME_OPEN_PATH|RUNTIME_MARKER_OPEN_PATH)/,
      'Use a harmless test file to verify the path and extension policy without running an untrusted executable.'],
    ['Download or shortcut destination', /^(DOWNLOAD|WRITE_SHORTCUT)/,
      'Inspect the final target path and whether the input originates from a page or fixed app configuration.'],
  ],
  'Command or Code Execution from Variable Input': [
    ['Shell command construction', /^(COMMAND_INJECTION|RUNTIME_MARKER_COMMAND)/,
      'Trace the value to the process API; use a harmless marker to separate data flow from actual command execution.'],
    ['Dynamic code evaluation', /^DANGEROUS_FUNCTIONS/,
      'Identify the evaluated value and its source; test with a benign marker in an isolated environment.'],
    ['Untrusted module path', /^(DYNAMIC_MODULE|RUNTIME_MARKER_MODULE)/,
      'Trace the module path to its source; a watch session with the marker in that value shows whether it reaches require() or import().'],
  ],
  'Insecure Microsoft Word Integration': [
    ['Word launch command', /^WORD_LAUNCH/,
      'Inspect the Word invocation and confirm the final argument array and document location.'],
    ['Document provenance and Protected View', /^(WORD_LAUNCH|RUNTIME_OPEN_PATH|RUNTIME_MARKER_OPEN_PATH)/,
      'On Windows, inspect the actual opened file with Get-Item <doc> -Stream Zone.Identifier.'],
  ],
  'Insecure Handling of Deep Links and File Associations': [
    ['External handler input', /^(FILE_HANDLER|PROTOCOL_HANDLER|INSTALLER_FILE_HANDLER)/,
      'Inspect the registered command and follow a benign crafted link or file through the parser.'],
    ['Privileged custom scheme or file URL', /^(PROTOCOL_PRIVILEGES|FILE_PROTOCOL)/,
      'Check scheme privileges, resource resolution and the final URL loaded by each window.'],
  ],
  'Insufficient Navigation and New Window Restrictions': [
    ['Untrusted URL loaded in an app window', /^UNTRUSTED_LOAD_URL/,
      'Trace the URL passed to loadURL to its input, and load a benign crafted destination in an authorised test.'],
    ['Top-level navigation or redirect', /^(LIMIT_NAVIGATION|NAVIGATION_REDIRECT|RUNTIME_NAVIGATION|RUNTIME_REDIRECT|RUNTIME_MARKER_NAVIGATION)/,
      'Exercise a benign external link and redirect while recording the final URL and window settings.'],
    ['Popup or middle-click', /^(WINDOW_OPEN_HANDLER|AUXCLICK|ALLOWPOPUPS|RUNTIME_NEW_WINDOW|RUNTIME_MARKER_NEW_WINDOW)/,
      'Test a benign popup and middle-click in the affected renderer and inspect its options.'],
    ['Embedded content', /^(WEBVIEW|IFRAME_SANDBOX|RUNTIME_WEBVIEW)/,
      'Inspect webview attachment and iframe sandbox attributes for the actual loaded source.'],
  ],
  'Permissive Browser Permission Handling': [
    ['Permission request callback', /^(PERMISSION_REQUEST_HANDLER|RUNTIME_PERMISSION$)/,
      'Request a benign permission from the affected origin and record the handler and decision.'],
    ['Synchronous permission check', /^RUNTIME_PERMISSION_CHECK/,
      'Inspect setPermissionCheckHandler and observe the origin and permission in a watch session.'],
  ],
  'Cross-Site Scripting in Content Rendering': [
    ['HTML sink or editor', /^(XSS_SINK|RICH_TEXT_EDITOR|RUNTIME_DOM_INJECTION|RUNTIME_HTML_ENDPOINT)/,
      'Follow a harmless unique marker from its input to the rendered sink; distinguish text from live HTML and script execution.'],
    ['Sanitiser or framework bypass', /^(SANITIZER_CONFIG|ANGULAR)/,
      'Inspect the configured allowlist and the exact binding that consumes the value.'],
    ['Runtime reflection or message', /^(RUNTIME_MARKER|RUNTIME_ACTIVE_SCRIPT|RUNTIME_CAMPAIGN_SCRIPT|TRAFFIC_WS_HTML_MESSAGE|TRAFFIC_REFLECTED_INPUT)/,
      'Compare the source user, destination view, DOM interpretation and execution signal from the same session.'],
    ['Markup without proven execution', /^RUNTIME_MARKER/,
      'Check the same marker in the destination DOM and record whether a harmless script can run.', i => !executed(i)],
    ['Script execution observed', /^(RUNTIME_ACTIVE_SCRIPT|RUNTIME_CAMPAIGN_SCRIPT)/,
      'Match the execution event to the saved input, destination user and renderer settings in the same session.'],
  ],
  'Missing or Insufficient Content Security Policy': [
    ['No effective policy', /^(CSP$|CSP_DIRECTIVES)/,
      'Check the live response headers and meta elements for an enforceable policy, including redirects and frames.', noPolicy],
    ['Unsafe script directives', /^(CSP$|CSP_DIRECTIVES)/,
      'Inspect the effective script-src directive, nonces, hashes and report-only status in the affected window.', i => !noPolicy(i)],
    ['Runtime violation or mismatch', /^RUNTIME_CSP/,
      'Record the effective runtime policy and violation details before changing it.'],
    ['Script evaluation permitted', /^RUNTIME_CAMPAIGN_EVAL$/,
      'Check the effective script-src of the tested view for unsafe-eval and repeat the campaign case.'],
  ],
  'Insecure Processing of Untrusted Documents': [
    ['Untrusted document intake', /^DOCUMENT_PIPELINE/,
      'Identify the accepted formats, parser and isolation boundary; use a benign malformed fixture where authorised.'],
    ['Rendered conversion output', /^DOCUMENT_PIPELINE/,
      'Compare a harmless document’s converted output with the renderer’s HTML and resource requests.',
      i => /markdown|html|convert|render|output/i.test(describe(i))],
  ],
  'Insecure Electron Fuse Configuration': [
    ['Local Node entry points', /^(FUSES|PACKAGED_FUSES)/,
      'Read the packaged fuse values and compare them with the build configuration.',
      fuses(['RunAsNode', 'EnableNodeOptionsEnvironmentVariable', 'EnableNodeCliInspectArguments'])],
    ['Asar integrity and loading', /^(FUSES|PACKAGED_FUSES)/,
      'Check both fuse values and the executable’s embedded integrity digest.',
      fuses(['EnableEmbeddedAsarIntegrityValidation', 'OnlyLoadAppFromAsar'])],
    ['Cookie or file-protocol privileges', /^(FUSES|PACKAGED_FUSES)/,
      'Inspect the relevant fuse and confirm actual cookie storage and file URL use.',
      fuses(['EnableCookieEncryption', 'GrantFileProtocolExtraPrivileges'])],
  ],
  'Application Code Not Protected Against Tampering or Disclosure': [
    ['Source map exposure', /^SOURCE_MAP_SHIPPED/,
      'Locate shipped .map files and check whether they include sourcesContent.'],
    ['Asar integrity', /^ASAR_INTEGRITY/,
      'Compare the packaged archive, embedded digest and integrity-related fuses.'],
  ],
  'Missing Code Signing or Exploit Mitigations': [
    ['Publisher signature', /^CODE_SIGNING/,
      'Verify the signature with the operating system and record the signer and timestamp.'],
    ['Platform exploit mitigations', /^BINARY_HARDENING/,
      'Inspect mitigation flags in the exact shipped binary and any native modules.'],
  ],
  'Insecure Software Update Mechanism': [
    ['Update feed transport', /^UPDATE_SECURITY/,
      'Inspect the packaged feed URL and observe a benign update check.', i => !/signature|downgrade|publisher/i.test(describe(i))],
    ['Update signature or publisher', /^UPDATE_SECURITY/,
      'Check the updater implementation and a deliberately invalid test signature in an isolated environment.',
      i => /signature|downgrade|publisher/i.test(describe(i))],
  ],
  'Debugging Features Enabled in Production': [
    ['Developer tooling or test hooks', /^(DEVTOOLS|DEVELOPMENT_CODE)/,
      'Inspect the packaged build and exercise only the documented development entry point.'],
    ['Logs, console secrets or exceptions', /^(DEBUG_LOGGING|RUNTIME_SECRET_IN_CONSOLE|RUNTIME_UNCAUGHT_EXCEPTION)/,
      'Check the recorded line or watch event and its actual value and retention path.'],
  ],
  'Hard-coded Secrets in the Application Package': [
    ['Credential or token in code', /^HARDCODED_SECRET/,
      'Identify the provider, scope, validity and whether the value is a secret rather than a public identifier.',
      i => !PUBLIC_SECRET.test(props(i).kind || describe(i))],
    ['Public key or false positive', /^HARDCODED_SECRET/,
      'Verify the provider’s classification and effective permissions before raising the final impact.',
      i => confidenceOf(i) === 'TENTATIVE' || PUBLIC_SECRET.test(props(i).kind || describe(i))],
  ],
  'Sensitive Data Stored Without Adequate Protection': [
    ['Plaintext credential or file', /^(STORAGE_(CREDENTIAL|SECRET)|SECRET_FILE_WRITE|PLAINTEXT_SECRETS)/,
      'Identify the exact store and compare a benign canary before and after the save operation.'],
    ['Application settings or cached responses', /^(ELECTRON_STORE_ENCRYPTION|STORAGE_CACHED_RESPONSES|STORAGE_COOKIE_AT_REST)/,
      'Inspect the exact stored value and protection without copying real user secrets into the report.'],
  ],
  'Certificate Pinning Not Implemented': [
    ['No certificate pinning', /^CERTIFICATE_PINNING/,
      'Decide whether the threat model requires pinning; test the exact app connection and host with a known proxy certificate.'],
    ['HTTPS exchanges in a proxy capture', /^CERTIFICATE_PINNING/,
      'Establish the originating app, captured hosts and proxy certificate before treating the capture as a pinning test.', i => validationResults(i).some(r => r.scope === 'capture')],
  ],
  'Insecure Network Transport and Certificate Validation': [
    ['Cleartext HTTP or WebSocket', /^(HTTP_RESOURCES|RUNTIME_INSECURE_LOAD|TRAFFIC_CLEARTEXT_HTTP|TRAFFIC_WS_CLEARTEXT)/,
      'Confirm the final scheme and host in a capture or live load.'],
    ['Certificate validation bypass', /^(CERTIFICATE_(ERROR_EVENT|VERIFY_PROC)|NODE_TLS_REJECT_UNAUTHORIZED|RUNTIME_CERTIFICATE_ERROR|CUSTOM_ARGUMENTS)/,
      'Identify the exact session, host and callback result; distinguish a rejected error from an accepted one.',
      i => !/^CUSTOM_ARGUMENTS/.test(i.id) || /ignore-certificate-errors/i.test(describe(i))],
    ['Credential transport or cookie flags', /^(TRAFFIC_BASIC_AUTH|TRAFFIC_INSECURE_COOKIE|COOKIE_FLAGS)/,
      'Inspect the captured request and Set-Cookie attributes for the affected host.'],
  ],
  'Sensitive Data Exposed in Network Traffic': [
    ['Secret in URL or response', /^(TRAFFIC_SECRET_IN_URL|TRAFFIC_SECRET_IN_RESPONSE)/,
      'Confirm the value type and recipient using a benign account or redacted capture.'],
    ['WebSocket secret', /^TRAFFIC_WS_SECRET/,
      'Record the socket endpoint and the message recipient without disclosing the secret itself.'],
    ['Third-party destination', /^(TRAFFIC_AUTH_TO_THIRD_PARTY|TRAFFIC_USER_INPUT_TO_THIRD_PARTY)/,
      'Confirm host ownership, request purpose and whether the value can be removed or minimised.'],
  ],
  'Outdated Software Components': [
    ['Unsupported release line', /^UNSUPPORTED_VERSION/,
      'Confirm the packaged version and the current supported release lines.'],
    ['Missing Electron or Chromium fixes', /^(AVAILABLE_SECURITY_FIXES|CHROMIUM_ADVISORIES)/,
      'Compare the exact bundled versions and applicable advisories, including backports.'],
    ['Published dependency advisory', /^DEPENDENCY_VULNERABILITIES/,
      'Match package and version to advisory conditions and the affected import or bundle.'],
    ['Unsupported library', /^END_OF_LIFE_LIBRARY/,
      'Confirm the shipped copy and its support status; check whether it is used at runtime.'],
  ],
  'Known Malicious Software Package': [
    ['Malicious version in inventory', /^MALICIOUS_DEPENDENCY/,
      'Confirm the exact version, source, installation time and any install scripts or build use.'],
    ['Exposure response', /^MALICIOUS_DEPENDENCY/,
      'Review package execution and access logs before deciding which credentials and artefacts were exposed.'],
  ],
};

/** Variations supported by the checks in this group and by the data of each finding. */
export function matchingVariations(title, issues, normalise) {
  const entries = (VARIATIONS[title] || []).map(([label, pattern, evidence, when]) => ({
    label, description: CLIENT_COPY[label][0], implication: CLIENT_COPY[label][1], evidence, recommendation: CLIENT_COPY[label][2], pattern,
    issues: issues.filter(i => pattern.test(normalise(i.id)) && (!when || when(i))),
  }));
  // a finding whose data selects none of its check's scenarios gets the first of them
  for (const issue of issues) {
    if (entries.some(v => v.issues.includes(issue))) continue;
    const first = entries.find(v => v.pattern.test(normalise(issue.id)));
    if (first) first.issues.push(issue);
  }
  const matched = entries.filter(v => v.issues.length).map(({ pattern, ...v }) => v);
  // a newly added check or catch-all observation still receives a complete variation across every section, one per check
  const unmatched = issues.filter(issue => !matched.some(v => v.issues.includes(issue)));
  for (const id of [...new Set(unmatched.map(issue => issue.id))]) matched.push({
    label: id, description: 'Testing identified additional security-relevant behaviour, described under Reproduction and Evidence.',
    implication: 'Depending on how the affected functionality can be reached, it could weaken the security of the application or expose data or functionality to an attacker.',
    evidence: 'Inspect the recorded location and confirm the actual input source and behaviour.',
    recommendation: 'Review the affected functionality and its intended callers, apply the guidance referenced below, and verify that unauthorised input is rejected in the packaged application.',
    issues: unmatched.filter(issue => issue.id === id),
  });
  return matched;
}
