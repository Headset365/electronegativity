// Client-facing findings, grouped by the security problem rather than by scanner check.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { consequenceOf, interactionOf, validationHint } from '../finder/consequences.js';
import { remediationOf } from '../finder/remediation.js';
import { matchingVariations } from './markdown_variations.js';
import { executionConfirmed, mergeFindingEvidence, validationResults } from '../finder/validation.js';
import { OUTDATED_TITLE, outdatedSections } from './markdown_outdated.js';

const definitions = [
  ['Renderer Isolation Weakened', /^(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX|REMOTE_MODULE|AFFINITY|PRELOAD|HTTP_RESOURCES_WITH_NODE_INTEGRATION|RUNTIME_(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX)|RUNTIME_CAMPAIGN_(NODE|ELECTRON|FS_READ)$)/, 'Untrusted content may gain access to privileged application capabilities.', 'Isolate renderers, disable Node integration and keep the sandbox enabled.', 'CWE-653: Improper Isolation or Compartmentalization'],
  ['Chromium Security Features Disabled', /^(WEB_SECURITY|INSECURE_CONTENT|EXPERIMENTAL_FEATURES|BLINK_FEATURES|WEBGL|WEBSQL|PLUGINS|NAVIGATE_ON_DRAG_DROP|CUSTOM_ARGUMENTS|SECURITY_WARNINGS_DISABLED|SECUREKEYBOARDENTRY|RUNTIME_WEB_SECURITY)/, 'Disabled browser safeguards expand what page content can do.', 'Restore Chromium defaults and enable only capabilities that are essential.', 'CWE-693: Protection Mechanism Failure'],
  ['Privileged APIs Exposed to Untrusted Content', /^(CONTEXT_BRIDGE_EXPOSURE|RUNTIME_PRELOAD_FOREIGN_ORIGIN|WINDOW_SESSION|RUNTIME_WINDOW_SESSION)/, 'Untrusted pages may reach privileged APIs or share a trusted session.', 'Expose narrow preload APIs and separate sessions by trust level.', 'CWE-749: Exposed Dangerous Method or Function'],
  ['IPC Handlers Trust Renderer Input', /^(IPC_SENDER_VALIDATION|IPC_HANDLER|IPC_FILE_ACCESS|IPC_CHANNEL_MAP|RUNTIME_MARKER_IPC)/, 'Renderer messages can reach main-process operations without adequate checks.', 'Validate the sender, arguments and allowed operations in every handler.', 'CWE-20: Improper Input Validation'],
  ['Unsafe Hand-off of URLs and Files to the Operating System', /^(OPEN_EXTERNAL|OPEN_PATH|SHOWITEMINFOLDER|WRITE_SHORTCUT|DOWNLOAD|RUNTIME_(OPEN_EXTERNAL|OPEN_PATH)|RUNTIME_MARKER_(OPEN_EXTERNAL|OPEN_PATH))/, 'Untrusted URLs or file paths may be opened by the operating system.', 'Allowlist URL schemes and hosts, and constrain file paths before opening them.', 'CWE-73: External Control of File Name or Path'],
  ['Code or Command Execution from Untrusted Data', /^(COMMAND_INJECTION|DANGEROUS_FUNCTIONS|DYNAMIC_MODULE|RUNTIME_MARKER_(COMMAND|MODULE))/, 'Untrusted data may reach command or code execution.', 'Avoid command-line construction and pass validated arguments to safe APIs.', 'CWE-78: Improper Neutralization of Special Elements used in an OS Command'],
  ['Microsoft Word Integration', /^WORD_LAUNCH/, 'Opening documents in Microsoft Word can expose users to unsafe document content or command construction.', 'Validate document paths and preserve Mark-of-the-Web metadata before opening files.', 'CWE-73: External Control of File Name or Path'],
  ['Deep Link, Protocol and File Association Handling', /^(FILE_HANDLER|PROTOCOL_HANDLER|PROTOCOL_PRIVILEGES|INSTALLER_FILE_HANDLER|FILE_PROTOCOL)/, 'External links and files can enter privileged application flows.', 'Parse deep links and file associations as untrusted input and allow only known actions.', 'CWE-20: Improper Input Validation'],
  ['Insufficient Navigation and Window Controls', /^(LIMIT_NAVIGATION|UNTRUSTED_LOAD_URL|WINDOW_OPEN_HANDLER|NAVIGATION_REDIRECT|AUXCLICK|ALLOWPOPUPS|WEBVIEW|IFRAME_SANDBOX|RUNTIME_(NAVIGATION|NEW_WINDOW|REDIRECT|WEBVIEW)|RUNTIME_MARKER_(NAVIGATION|NEW_WINDOW))/, 'Untrusted navigation or new windows may retain application privileges.', 'Deny navigation and new windows by default, then allowlist intended destinations.', 'CWE-601: URL Redirection to Untrusted Site'],
  ['Missing Permission Handlers', /^(PERMISSION_REQUEST_HANDLER|RUNTIME_PERMISSION|RUNTIME_PERMISSION_CHECK)/, 'Pages may obtain capabilities without an explicit application decision.', 'Install request and check handlers that deny permissions by default.', 'CWE-862: Missing Authorization'],
  ['Cross-Site Scripting Exposure in Content Rendering', /^(XSS_SINK|RICH_TEXT_EDITOR|SANITIZER_CONFIG|ANGULAR|RUNTIME_DOM_INJECTION|RUNTIME_MARKER|RUNTIME_HTML_ENDPOINT|RUNTIME_(ACTIVE_SCRIPT|CAMPAIGN_SCRIPT)|TRAFFIC_WS_HTML_MESSAGE|TRAFFIC_REFLECTED_INPUT)/, 'Untrusted content may be rendered as executable markup.', 'Render text as text; sanitise allowed HTML before insertion into the page.', 'CWE-79: Improper Neutralization of Input During Web Page Generation'],
  ['Missing or Weak Content Security Policy', /^(CSP$|CSP_DIRECTIVES|RUNTIME_CSP|RUNTIME_CAMPAIGN_EVAL$)/, 'A missing or permissive policy reduces protection against script injection.', 'Ship a restrictive Content Security Policy for every renderer.', 'CWE-693: Protection Mechanism Failure'],
  ['Document Parsing Risks', /^DOCUMENT_PIPELINE/, 'Documents enter parsers or renderers that need strict isolation.', 'Validate file types and parse untrusted documents in a restricted context.', 'CWE-20: Improper Input Validation'],
  ['Insecure Electron Fuse Configuration', /^(FUSES|PACKAGED_FUSES)/, 'Packaged Electron fuses leave unnecessary privileges available.', 'Set secure fuses at package time and verify the packaged executable.', 'CWE-693: Protection Mechanism Failure'],
  ['Application Code Not Protected Against Inspection or Tampering', /^(ASAR_INTEGRITY|SOURCE_MAP_SHIPPED)/, 'Packaged application code may be exposed or changed without detection.', 'Remove production source maps and enable asar integrity with the associated fuses.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Executable Signing and Exploit Mitigations (hardening)', /^(CODE_SIGNING|BINARY_HARDENING)/, 'The executable lacks a signing or binary hardening safeguard.', 'Sign releases and enable platform exploit mitigations.', 'CWE-693: Protection Mechanism Failure'],
  ['Insecure Update Mechanism', /^UPDATE_SECURITY/, 'The update channel may install software without sufficient verification.', 'Use an authenticated update channel and verify publisher signatures.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Development and Debugging Features in Production', /^(DEVTOOLS|DEVELOPMENT_CODE|DEBUG_LOGGING|RUNTIME_SECRET_IN_CONSOLE|RUNTIME_UNCAUGHT_EXCEPTION)/, 'Development features can disclose information or expand the attack surface.', 'Remove debug facilities and sensitive logs from production builds.', 'CWE-489: Active Debug Code'],
  ['Hard-coded Secrets in the Application Package', /^HARDCODED_SECRET/, 'Secrets shipped in the application package can be recovered by anyone with the package.', 'Remove and rotate embedded secrets; keep server credentials on the server.', 'CWE-798: Use of Hard-coded Credentials'],
  ['Sensitive Data Stored Insecurely', /^(STORAGE|SECRET_FILE_WRITE|ELECTRON_STORE_ENCRYPTION|PLAINTEXT_SECRETS)/, 'Sensitive data may be recoverable from local storage.', 'Use the operating system credential store or safeStorage for secrets.', 'CWE-312: Cleartext Storage of Sensitive Information'],
  ['Certificate Pinning Not Implemented (hardening)', /^CERTIFICATE_PINNING/, 'Backend connections trust any certificate the operating system trusts.', 'Pin backend certificates or keys where the threat model requires it.', 'CWE-295: Improper Certificate Validation'],
  ['Insecure Transport and Certificate Validation', /^(HTTP_RESOURCES|RUNTIME_INSECURE_LOAD|TRAFFIC_(CLEARTEXT_HTTP|WS_CLEARTEXT|BASIC_AUTH|INSECURE_COOKIE)|COOKIE_FLAGS|CERTIFICATE|NODE_TLS_REJECT_UNAUTHORIZED|RUNTIME_CERTIFICATE_ERROR)/, 'Traffic or credentials may be exposed in transit.', 'Use HTTPS and WSS, validate certificates and set secure cookie attributes.', 'CWE-319: Cleartext Transmission of Sensitive Information'],
  ['Sensitive Data Exposed in Network Traffic', /^(TRAFFIC_(SECRET_IN_URL|SECRET_IN_RESPONSE|WS_SECRET|AUTH_TO_THIRD_PARTY|USER_INPUT_TO_THIRD_PARTY))/, 'Network requests may expose credentials or user data to unintended recipients.', 'Restrict data sent to each host and remove secrets from URLs and responses.', 'CWE-201: Insertion of Sensitive Information Into Sent Data'],
  // the Electron runtime and third-party components, in one finding that refers to the components workbook
  [OUTDATED_TITLE, /^(AVAILABLE_SECURITY_FIXES|UNSUPPORTED_VERSION|CHROMIUM_ADVISORIES|DEPENDENCY_VULNERABILITIES|END_OF_LIFE_LIBRARY)/, 'The application uses outdated software components.', 'Upgrade or replace each affected component.', 'CWE-1104: Use of Unmaintained Third Party Components'],
  ['Known Malicious Package', /^MALICIOUS_DEPENDENCY/, 'A known malicious package was detected in the dependency inventory.', 'Remove the package immediately and rotate potentially exposed secrets.', 'CWE-506: Embedded Malicious Code'],
];

const other = ['Other Security Observations', null, 'Additional scanner observations require assessment.', 'Investigate the listed observations and apply the linked guidance.', 'CWE-693: Protection Mechanism Failure'];
// These paragraphs describe the problem type; the check bullets below them state what the scan actually found.
const introductions = {
  'Renderer Isolation Weakened': 'One or more renderers in {app} have reduced separation from privileged application code. The listed settings can increase the harm from untrusted page content if that content reaches the affected window.',
  'Chromium Security Features Disabled': '{app} changes browser security settings or starts Chromium with switches that weaken its protections. These changes apply to the affected content regardless of whether a particular exploit was observed during the scan.',
  'Privileged APIs Exposed to Untrusted Content': '{app} exposes privileged APIs or a shared session to content with a different trust level. The affected bridge, preload or session needs to be restricted to the origins and operations the application intends to trust.',
  'IPC Handlers Trust Renderer Input': 'The listed IPC entry points in {app} accept data from renderers or expose main-process behaviour. Sender identity, argument shape and the permitted operation need to be checked at the handler boundary.',
  'Unsafe Hand-off of URLs and Files to the Operating System': '{app} passes URLs or paths to operating-system APIs. If a document, link or renderer can control those values, a crafted input may cause the host to open an unintended resource.',
  'Code or Command Execution from Untrusted Data': '{app} contains an execution path involving data that may come from a less trusted source. The listed evidence identifies the path; control of the command or code must be established before treating it as a confirmed exploit.',
  'Microsoft Word Integration': '{app} launches Microsoft Word or opens documents that may be supplied by other people. The launch arguments, document path and preservation of Mark-of-the-Web determine whether this flow exposes a user to additional risk.',
  'Deep Link, Protocol and File Association Handling': '{app} accepts external URLs or files through registered handlers. These entry points cross from an untrusted operating-system input into application code and should accept only recognised actions and paths.',
  'Insufficient Navigation and Window Controls': 'The affected windows in {app} may navigate to unintended destinations or open additional content. Controls must cover redirects, popups and embedded views as well as direct navigation.',
  'Missing Permission Handlers': '{app} has a missing or permissive decision point for browser permissions. A request should be checked against the requesting origin and the specific capability before it is granted.',
  'Cross-Site Scripting Exposure in Content Rendering': '{app} has a path that may render untrusted data as HTML or script-bearing content. A sink or live markup observation alone does not prove attacker control or script execution unless the runtime evidence says so.',
  'Missing or Weak Content Security Policy': 'The affected pages in {app} have a missing or permissive Content Security Policy. A restrictive policy can limit the effects of injected markup, but it does not replace safe rendering.',
  'Document Parsing Risks': '{app} imports or parses documents through the listed components. The risk depends on the document formats, parser versions and whether an untrusted document reaches those paths.',
  'Insecure Electron Fuse Configuration': 'The packaged Electron settings for {app} leave one or more hardening fuses in an insecure state. These settings affect local execution and package integrity; they do not by themselves show a remote attack path.',
  'Application Code Not Protected Against Inspection or Tampering': 'The distributed code in {app} may be easier to inspect or modify than intended. Source maps expose implementation details, while asar integrity depends on the packaged digest and matching fuses.',
  'Executable Signing and Exploit Mitigations (hardening)': 'The executable or installer for {app} lacks one or more release hardening measures. Signing and platform mitigations reduce tampering and exploitation opportunities but do not prove an active vulnerability.',
  'Insecure Update Mechanism': 'The update configuration in {app} may accept releases without adequate transport or publisher verification. The update channel is a supply path and must be checked in the packaged build.',
  'Development and Debugging Features in Production': 'The production package of {app} retains development or debugging behaviour. The listed items can expose information or expand the actions available to someone using the app.',
  'Hard-coded Secrets in the Application Package': '{app} contains material identified as a secret in its distributed files. Anyone with the package can inspect those files; the value and its privileges should be checked before rotation.',
  'Sensitive Data Stored Insecurely': '{app} stores or writes sensitive data through the listed paths. The effective exposure depends on the data involved, its protection at rest and access to the user profile or package.',
  'Certificate Pinning Not Implemented (hardening)': '{app} validates server certificates against the certificate authorities the operating system trusts, without pinning the certificates or keys of its own backends. Certificates are still validated; pinning is an additional safeguard whose need depends on the threat model.',
  'Insecure Transport and Certificate Validation': '{app} loads or sends data through insecure transport settings or bypasses certificate checks. The affected URL, certificate path or cookie determines which traffic may be exposed.',
  'Sensitive Data Exposed in Network Traffic': 'The captured traffic from {app} contains data or destinations that may disclose credentials or user input. The listed hosts and fields need to be checked against the client’s intended data flows.',
  'Known Malicious Package': 'A package version identified as malicious is present in the dependency inventory for {app}. Its role in the build and any exposure of credentials or developer machines should be investigated promptly.',
  'Other Security Observations': '{app} has a reportable scanner observation outside the named groups. The check description and evidence below identify the affected component and what needs to be assessed.',
};
// (PRELOAD_JS_CHECK is informational with context isolation, reported without: the preload then shares the page's world)
const evidenceOnly = /^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|IPC_RENDERER_CHANNEL|RUNTIME_IPC$|RUNTIME_MARKER_SENT|CREDENTIAL_ACCESS|DEPENDENCY_INVENTORY|ELECTRON_VERSION)/;
const observations = new Set(['SOURCE_MAP_SHIPPED', 'STORAGE_CACHED_RESPONSES', 'CERTIFICATE_PINNING', 'WORD_LAUNCH']);
// findings whose Reproduction and Evidence lists only validated instances
const VALIDATED_EVIDENCE_ONLY = new Set(['Cross-Site Scripting Exposure in Content Rendering']);
const normalId = id => String(id || '').replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, '');
const nameOf = i => i?.name || i || '';
// Script execution or a tested capability. Live markup and observed settings do not establish exploitation.
// (the campaign's Node, Electron, file and eval findings exist only when the payload's script ran and signalled them)
const isConfirmed = executionConfirmed;
// validation not run (a static observation with no runtime result), or its best result inconclusive. A screenshot is
// runtime evidence: an instance carrying one is never left out
const unvalidated = i => !(i.properties?.screenshot || i.properties?.screenshots?.length) && (validationResults(i).length
  ? i.validation?.status === 'inconclusive' : !isConfirmed(i) && !/^RUNTIME_|^TRAFFIC_/.test(i.id));
const victimAction = i => /\b(click|open|install|updat|import|attachment|document)/i.test(interactionOf(i.id) || '');
const consequenceScale = ['Very Low', 'Low', 'Medium', 'High', 'Critical'];
const likelihoodScale = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Very Likely'];
const definitionOf = title => definitions.find(d => d[0] === title);
// how much of the app's own text and code one report entry shows (a minified bundle is one line of megabytes)
const SAMPLE_LIMIT = 600;
const TEXT_LIMIT = 500;
const MAX_LOCATIONS = 60;
const MAX_INSTANCES = 12;
// commands that check a finding by hand, per group
const COMMANDS = {
  'Insecure Electron Fuse Configuration': 'npx @electron/fuses read --app "<exe>"',
  'Application Code Not Protected Against Inspection or Tampering': 'npx @electron/asar extract app.asar out',
  'Microsoft Word Integration': 'Get-Item <doc> -Stream Zone.Identifier',
};

function reportable(i) {
  const id = normalId(i.id);
  if (/_(DEPRECATION|REMOVAL|CHANGE)$/.test(id) || id === 'IPC_SEND_STRUCTURED_CLONE_ALGORITHM' ||
      ['TRAFFIC_IDOR_CANDIDATE', 'TRAFFIC_STATE_CHANGE_NO_AUTH'].includes(id) || /COVERAGE/.test(id) ||
      id === 'RUNTIME_CSP_VIOLATION' ||
      // the tool's own housekeeping during a campaign (restoring the test record, removing its canaries), not the app's
      ['RUNTIME_CAMPAIGN_RESTORE', 'RUNTIME_CAMPAIGN_CLEANUP'].includes(id)) return false;
  if (evidenceOnly.test(id) || /^(CSP_(JS|HTML)|NAVIGATION_REDIRECT_JS)_CHECK$/.test(i.id) || (id === 'RUNTIME_MARKER' && !i.properties?.live) ||
      (['IPC_HANDLER', 'IPC_CHANNEL_MAP', 'DOCUMENT_PIPELINE'].includes(id) && nameOf(i.severity) === 'INFORMATIONAL')) return false;
  return nameOf(i.severity) !== 'INFORMATIONAL' || observations.has(id);
}

function groupOf(i) {
  const id = normalId(i.id);
  if (['RUNTIME_OPEN_PATH', 'RUNTIME_MARKER_OPEN_PATH'].includes(id) && /\.(?:docx?|rtf)\b/i.test(i.description || '')) return definitionOf('Microsoft Word Integration');
  return definitions.find(g => g[1].test(id)) || other;
}

function evidenceGroupOf(i) {
  const id = normalId(i.id);
  if (id === 'RUNTIME_CSP_VIOLATION') return 'Missing or Weak Content Security Policy';
  if (/^RUNTIME_DOCX_/.test(id)) return 'Document Parsing Risks';
  if (id === 'RUNTIME_WINDOW_COVERAGE') return 'Renderer Isolation Weakened';
  if (/^RUNTIME_(CAMPAIGN|ACTIVE|ENTRY)_COVERAGE$/.test(id) || /^RUNTIME_CAMPAIGN_(RESTORE|CLEANUP)$/.test(id))
    return ['Cross-Site Scripting Exposure in Content Rendering', 'Renderer Isolation Weakened', 'Missing or Weak Content Security Policy', 'Document Parsing Risks'];
  if (/^RUNTIME_CAMPAIGN_/.test(id)) {
    const name = i.properties?.case || '';
    if (name.startsWith('nav-')) return 'Insufficient Navigation and Window Controls';
    if (['node', 'electron', 'fs-read'].includes(name)) return ['Renderer Isolation Weakened', 'Cross-Site Scripting Exposure in Content Rendering'];
    if (name === 'eval') return ['Missing or Weak Content Security Policy', 'Cross-Site Scripting Exposure in Content Rendering'];
    return 'Cross-Site Scripting Exposure in Content Rendering';
  }
  if (/^RUNTIME_MARKER_(NAVIGATION|NEW_WINDOW)$/.test(id)) return 'Insufficient Navigation and Window Controls';
  if (/^RUNTIME_MARKER_OPEN_(PATH|EXTERNAL)$/.test(id)) return groupOf(i)[0];
  if (/^RUNTIME_MARKER_(COMMAND|MODULE)$/.test(id)) return 'Code or Command Execution from Untrusted Data';
  if (id === 'CSP') return 'Missing or Weak Content Security Policy';
  if (id === 'NAVIGATION_REDIRECT') return 'Insufficient Navigation and Window Controls';
  if (/^(RUNTIME_MARKER|RUNTIME_MARKER_SENT)$/.test(id)) return 'Cross-Site Scripting Exposure in Content Rendering';
  if (/^(IPC_HANDLER|IPC_CHANNEL_MAP|IPC_RENDERER_CHANNEL|RUNTIME_IPC|RUNTIME_MARKER_IPC)$/.test(id)) return 'IPC Handlers Trust Renderer Input';
  if (/^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|PRELOAD)$/.test(id)) return 'Renderer Isolation Weakened';
  if (id === 'DEPENDENCY_INVENTORY' || id === 'ELECTRON_VERSION') return OUTDATED_TITLE;
  if (id === 'CREDENTIAL_ACCESS') return 'Sensitive Data Stored Insecurely';
  if (id === 'DOCUMENT_PIPELINE') return 'Document Parsing Risks';
  return undefined;
}

export function ratingOf(i, title) {
  const id = normalId(i.id);
  const severity = nameOf(i.severity);
  // outdated components are rated Informational: the tool does not exploit the published vulnerabilities, and a tester
  // who does raises the rating by hand
  if (severity === 'INFORMATIONAL' || title === OUTDATED_TITLE ||
      title === 'Executable Signing and Exploit Mitigations (hardening)' && severity === 'LOW') return { consequence: 'N/A', likelihood: 'N/A' };
  const route = consequenceOf(i.id)?.route;
  let c = ({ HIGH: 3, MEDIUM: 2, LOW: 1 })[severity] ?? 0;
  if (route === 'local') c = Math.max(0, c - 1);
  // An execution probe proves execution in its tested renderer, not the account/privilege boundary of a full exploit.
  if (id === 'MALICIOUS_DEPENDENCY' || ['RUNTIME_ACTIVE_SCRIPT', 'RUNTIME_CAMPAIGN_SCRIPT'].includes(id) &&
      validationResults(i).some(r => r.status === 'confirmed' && r.scope === 'exploit')) c = 4;
  let l = isConfirmed(i) ? 4 : ({ CERTAIN: 3, FIRM: 2, TENTATIVE: 1 })[nameOf(i.confidence)] ?? 1;
  if (victimAction(i)) l--;
  if (route === 'local') l = Math.min(l, nameOf(i.confidence) === 'CERTAIN' ? 1 : 0);
  return { consequence: consequenceScale[c], likelihood: likelihoodScale[Math.max(0, l)] };
}

const rank = (r, scale) => r === 'N/A' ? -1 : scale.indexOf(r);
const byRating = (a, b) => rank(b.rating.consequence, consequenceScale) - rank(a.rating.consequence, consequenceScale) ||
  rank(b.rating.likelihood, likelihoodScale) - rank(a.rating.likelihood, likelihoodScale);

export function groupClientFindings(issues) {
  const groups = new Map();
  for (const i of issues.filter(reportable)) {
    const definition = groupOf(i);
    if (!groups.has(definition[0])) groups.set(definition[0], { definition, issues: [], evidence: [] });
    groups.get(definition[0]).issues.push(i);
  }
  for (const i of issues.filter(i => !reportable(i))) {
    const titles = evidenceGroupOf(i);
    for (const title of Array.isArray(titles) ? titles : [titles]) {
      const group = groups.get(title);
      if (group) group.evidence.push(i);
    }
  }
  return [...groups.values()].map(g => {
    g.items = g.issues.map(i => ({ issue: i, rating: ratingOf(i, g.definition[0]) })).sort(byRating);
    // most severe first everywhere the finding lists its instances, so a cut-off list never drops the one that rates it
    g.issues = g.items.map(x => x.issue);
    // accepted risks are listed but the rating is that of what is still open; a group of accepted risks only keeps theirs
    const basis = g.items.find(x => !x.issue.suppression) || g.items[0];
    g.rating = basis.rating;
    g.basis = basis.issue;
    g.accepted = !!basis.issue.suppression;
    return g;
  }).sort((a, b) => a.accepted - b.accepted || byRating(a, b) || a.definition[0].localeCompare(b.definition[0]));
}

function unique(values) { return [...new Set(values.filter(Boolean))]; }
function strings(value) { return (Array.isArray(value) ? value : value == null ? [] : [value]).filter(v => typeof v === 'string' && v.trim()); }
function noteValues(issues, field) { return unique(issues.flatMap(i => strings(i.notes?.[field]))); }
const scalar = value => typeof value === 'string' || typeof value === 'number' ? String(value) : undefined;
function language(file) {
  return ({ js: 'javascript', cjs: 'javascript', mjs: 'javascript', jsx: 'jsx', ts: 'typescript', tsx: 'tsx', json: 'json', html: 'html', css: 'css', ps1: 'powershell', sh: 'bash' })[path.extname(file || '').slice(1).toLowerCase()] || 'text';
}
function exampleLanguage(source) { return /^\s*</.test(source) ? 'html' : 'javascript'; }
const linkTarget = target => target.split('/').map(segment => encodeURIComponent(segment).replace(/\(/g, '%28').replace(/\)/g, '%29')).join('/');

/**
 * What every finding of one report shares: the app's name, the scanned folder (paths are shown relative to it, and to a
 * packaged app's install folder) and the home folder, which never appears in the report.
 */
function context(meta) {
  const root = meta.root ? path.resolve(meta.root) : undefined;
  const bases = root ? [root] : [];
  if (root && /[\\/]resources[\\/]app(\.asar)?$/i.test(root)) bases.push(path.dirname(path.dirname(root)));
  const home = os.homedir();
  const scrub = (value) => {
    let out = String(value ?? '');
    for (const base of bases) out = out.split(base + path.sep).join('').split(base).join(path.basename(base));
    return home && home.length > 1 ? out.split(home).join('~') : out;
  };
  return { app: meta.app?.name || 'the application', bases, scrub, outputFile: meta.outputFile, dependencies: meta.dependencies,
    reportRoot: meta.reportRoot || (meta.outputFile && path.dirname(path.resolve(meta.outputFile))), outputs: meta.outputs || [] };
}

function shownFile(file, ctx) {
  const value = String(file);
  if (!path.isAbsolute(value)) return value;
  for (const base of ctx.bases) {
    const relative = path.relative(base, value);
    if (!relative) return path.basename(base);
    if (!relative.startsWith('..') && !path.isAbsolute(relative)) return relative.split(path.sep).join('/');
  }
  return ctx.scrub(value).split(path.sep).join('/');
}

// Text from the scanned app (names, descriptions, evidence) is data: its Markdown and HTML syntax is escaped
function text(value, ctx, limit = TEXT_LIMIT) {
  let out = ctx.scrub(value).replace(/\s+/g, ' ').trim();
  if (out.length > limit) out = `${out.slice(0, limit)}…`;
  return out.replace(/[\\`*[\]<>]/g, '\\$&').replace(/&(?=#?\w+;)/g, '&amp;').replace(/^([#>+=-])/, '\\$1').replace(/^(\d+)([.)])/, '$1\\$2');
}

function codeSpan(value, limit = 300) {
  let out = String(value).replace(/\s+/g, ' ').trim();
  if (out.length > limit) out = `${out.slice(0, limit)}…`;
  const fence = '`'.repeat(Math.max(0, ...[...out.matchAll(/`+/g)].map(m => m[0].length)) + 1);
  const pad = out.startsWith('`') || out.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${out}${pad}${fence}`;
}

// A code block nested in the list item above it: indented, so no line of the code starts a line of the report (a `---`
// in the code can't be taken for the end of a finding), and cut to SAMPLE_LIMIT characters.
function codeBlock(value, lang, indent = '  ') {
  let source = String(value).replace(/\r\n?/g, '\n').replace(/^\n+|\s+$/g, '');
  const cut = Math.max(0, source.length - SAMPLE_LIMIT);
  if (cut) source = source.slice(0, SAMPLE_LIMIT);
  const fence = '`'.repeat(Math.max(3, ...[...source.matchAll(/`{3,}/g)].map(m => m[0].length + 1)));
  const block = [`${fence}${lang}`, ...source.split('\n'), fence].map(line => indent + line).join('\n');
  return cut ? `${block}\n\n${indent}(${cut} more characters not shown; see the location above.)` : block;
}

function place(i, ctx) {
  return !i.file || i.file === 'N/A' ? 'Application-wide' : `${shownFile(i.file, ctx)}${i.location?.line ? `:${i.location.line}` : ''}`;
}
function location(i, ctx) {
  const where = place(i, ctx);
  return where === 'Application-wide' ? where : codeSpan(where);
}
function details(i, ctx) {
  const p = i.properties || {};
  const pkg = scalar(p.package) || scalar(p.name);
  return [location(i, ctx), scalar(p.url) && codeSpan(ctx.scrub(p.url)), scalar(p.window) && text(p.window, ctx), scalar(p.channel) && `channel ${codeSpan(p.channel)}`,
    scalar(p.fuse) && `fuse ${codeSpan(`${p.fuse}=${scalar(p.value) ?? 'unknown'}`)}`, scalar(p.cookie) && `cookie ${codeSpan(p.cookie)}`, scalar(p.host) && codeSpan(p.host),
    pkg && codeSpan(`${pkg}${scalar(p.version) ? `@${p.version}` : ''}`), Array.isArray(p.advisories) && p.advisories.length && `${p.advisories.length} advisories`].filter(Boolean).join(' — ');
}

// a screenshot next to the report is linked; one elsewhere is named
function screenshot(file, ctx) {
  if (ctx.outputFile && path.isAbsolute(file)) {
    const relative = path.relative(path.dirname(path.resolve(ctx.outputFile)), file);
    const within = path.relative(path.resolve(ctx.reportRoot), file);
    if (within !== '..' && !within.startsWith(`..${path.sep}`) && !path.isAbsolute(within))
      return `[${text(path.basename(file), ctx)}](${linkTarget(relative.split(path.sep).join('/'))})`;
  }
  return codeSpan(ctx.scrub(file));
}
const screenshotOf = (i, ctx) => unique([i.properties?.screenshot, ...strings(i.properties?.screenshots)])
  .filter(f => typeof f === 'string').map(f => `; screenshot ${screenshot(f, ctx)}`).join('');

// Facts stay with their owning check. Arbitrary properties may contain credentials, so only known evidence fields are shown.
function recordedEvidence(i, ctx) {
  const p = i.properties || {};
  const lines = [`- **${text(i.id, ctx)}** at ${location(i, ctx)}${i.session ? `; session ${text(i.session, ctx)}` : ''}${screenshotOf(i, ctx)}`];
  const results = validationResults(i);
  for (const r of results) {
    lines.push(`  - Validation: **${text(r.status, ctx)}**${r.scope ? ` (${text(r.scope, ctx)})` : ''}${r.session ? `; session ${text(r.session, ctx)}` : ''}${r.text ? ` — ${text(r.text, ctx)}` : ''}`);
    for (const value of strings(r.evidence)) lines.push(`    - Evidence: ${text(value, ctx)}`);
  }
  if (!results.length) lines.push(`  - Validation: ${isConfirmed(i) ? 'script execution or tested capability recorded; wider exploitability unverified' : /^RUNTIME_|^TRAFFIC_/.test(i.id) ? 'runtime observation; exploitability unverified' : 'not run; static or artifact observation only'}`);
  if (i.location?.line > 0 && i.location?.column != null) lines.push(`  - Source column: ${text(i.location.column, ctx)}`);
  for (const value of strings(p.evidence)) lines.push(`  - Observed evidence: ${text(value, ctx)}`);
  const fields = ['campaignId', 'correlation', 'case', 'field', 'slot', 'delivery', 'savedValue', 'view', 'execution', 'signal', 'signals',
    'resources', 'method', 'route', 'webContents', 'page', 'frame', 'sender', 'sink', 'policy', 'directive', 'blocked', 'loaded',
    'request', 'resolved', 'program', 'source', 'count', 'accepted', 'viewOpened', 'loopbackRequested', 'sha256', 'bytes', 'verification', 'error',
    'expected', 'actual', 'enforced', 'format', 'missing', 'status', 'signer', 'verifiedBy', 'maps', 'inline', 'withSources', 'store',
    'origin', 'key', 'kind', 'basis', 'entries', 'weakEncryption', 'preload', 'partition', 'untried', 'unmatched', 'sent',
    'staticFinding', 'staticFindings', 'staticWindow', 'observedAt'];
  for (const field of fields) {
    const value = p[field];
    const printable = typeof value === 'boolean' ? String(value) : scalar(value) || strings(value).join(', ');
    if (printable) lines.push(`  - ${field}: ${text(printable, ctx)}`);
  }
  if (p.action) for (const field of ['clicked', 'navigated', 'url'])
    if (p.action[field] != null) lines.push(`  - action.${field}: ${text(p.action[field], ctx)}`);
  for (const [name, setting] of Object.entries(p.settings || {}))
    lines.push(`  - ${text(name, ctx)}: ${text(setting.value === undefined ? 'unavailable' : setting.value, ctx)} (${text(setting.source, ctx)})`);
  for (const f of p.frames || []) {
    lines.push(`  - Stack frame: ${codeSpan(ctx.scrub(`${f.url}:${f.line}:${f.column}`))}`);
    if (f.original) lines.push(`    - Original source: ${codeSpan(ctx.scrub(`${f.original.file}:${f.original.line}:${f.original.column}`))}`);
  }
  for (const advisory of p.advisories || []) {
    const value = typeof advisory === 'string' ? advisory : [advisory.id, ...strings(advisory.cves), advisory.severity, advisory.fixed && `fixed: ${advisory.fixed}`].filter(Boolean).join('; ');
    if (value) lines.push(`  - Advisory: ${text(value, ctx)}`);
  }
  for (const url of p.urls || []) lines.push(`  - Load target (${text(url.kind, ctx)}): ${text(url.value, ctx)}`);
  return lines.join('\n');
}

function proseNotes(g, ctx) {
  const i = g.basis;
  if (g.definition[0] === OUTDATED_TITLE) return ['Rated Informational: the known vulnerabilities of the listed components were not exploited during the engagement.',
    ...g.issues.filter(x => x.suppression).map(s => `Accepted risk — ${s.id} at ${text(place(s, ctx), ctx)}. ${s.suppression.reason ? text(s.suppression.reason, ctx) : 'No reason supplied.'}`)];
  const status = isConfirmed(i) ? 'runtime evidence recorded' : /^RUNTIME_/.test(i.id) ? 'observed at runtime; exploitability not established' : 'runtime exploitability not established';
  const notes = [`Rating basis: ${i.id} at ${text(place(i, ctx), ctx)}; scanner severity ${nameOf(i.severity)}, confidence ${nameOf(i.confidence)}; ${status}.`];
  notes.push('The scenarios below are conditional where the scan did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.');
  const open = g.issues.filter(issue => issue.manualReview && !isConfirmed(issue) && !issue.suppression);
  if (open.length) notes.push(`${open.length} instance${open.length === 1 ? '' : 's'} require${open.length === 1 ? 's' : ''} reachability or configuration review; exploitation has not been established for those instances.`);
  if (g.definition[0] === 'Sensitive Data Exposed in Network Traffic') notes.push('Establish ownership of each destination before characterising a transfer as third-party disclosure.');
  if (g.definition[0] === 'Microsoft Word Integration') notes.push('The Protected View scenario applies only where document provenance is lost in the actual opening workflow.');
  if (g.definition[0] === 'IPC Handlers Trust Renderer Input') notes.push('Channel-use conclusions depend on the shipped renderer and representative runtime coverage.');
  if (g.accepted) notes.push('Every instance of this finding is an accepted risk; the rating is that of the accepted instances.');
  else if (g.issues.some(x => x.suppression)) notes.push('Accepted risks are listed with this finding but do not set its rating.');
  for (const s of g.issues.filter(x => x.suppression)) {
    const { reason, owner, expires } = s.suppression;
    notes.push(`Accepted risk — ${s.id} at ${text(place(s, ctx), ctx)}. ${reason ? text(reason, ctx) : 'No reason supplied.'}${owner ? ` Owner ${text(owner, ctx)}.` : ''}${expires ? ` Expires ${text(expires, ctx)}.` : ''}`);
  }
  return notes;
}

// the outdated components finding: its own sections, pointing at the components workbook
function renderOutdated(g, ctx) {
  const [title, , , , cwe] = g.definition;
  const sections = outdatedSections({ app: text(ctx.app, ctx), dependencies: ctx.dependencies });
  const front = YAML.stringify({ Title: title, GeneratedBy: 'Electronegativity', Consequence: g.rating.consequence, Likelihood: g.rating.likelihood, Notes: proseNotes(g, ctx) }).trimEnd();
  const lines = [`---\n${front}\n---`, `# ${title}`,
    '## Issue Description', ...sections.description,
    '## Affected', ...sections.affected,
    '## Implication', ...sections.implication,
    '## Reproduction and Evidence', ...sections.evidence,
    '## Recommendations', ...sections.recommendations,
    '## References', ...sections.references, `- ${cwe}\n\n  https://cwe.mitre.org/data/definitions/${/^CWE-(\d+)/.exec(cwe)?.[1]}.html`];
  return lines.reduce((out, line) => out + (out && out.split('\n').at(-1).startsWith('- ') && line.startsWith('- ') ? '\n' : '\n\n') + line, '').trim();
}

function renderGroup(g, ctx) {
  const [title, , about, recommendation, cwe] = g.definition;
  if (title === OUTDATED_TITLE) return renderOutdated(g, ctx);
  const app = text(ctx.app, ctx);
  const ids = unique(g.issues.map(i => i.id));
  const variations = matchingVariations(title, g.issues, normalId);
  const labelsOf = issue => variations.filter(v => v.issues.includes(issue)).map(v => v.label);
  const accepted = i => i.suppression ? ' (accepted risk)' : '';
  const notes = field => noteValues(g.issues, field).map(value => `- ${text(value, ctx)}`);
  const front = YAML.stringify({ Title: title, GeneratedBy: 'Electronegativity', Consequence: g.rating.consequence, Likelihood: g.rating.likelihood, Notes: proseNotes(g, ctx) }).trimEnd();

  // each location once, with the scenarios it supports
  const affected = new Map();
  for (const i of g.issues) {
    const where = details(i, ctx);
    const entry = affected.get(where) || { labels: [], accepted: true };
    entry.labels.push(...labelsOf(i));
    entry.accepted = entry.accepted && !!i.suppression;
    affected.set(where, entry);
  }
  const places = [...affected].map(([where, entry]) => `- ${where} — ${unique(entry.labels).join('; ')}${entry.accepted ? ' (accepted risk)' : ''}`);

  // findings whose evidence lists only what was validated: an instance whose validation was not run, or was
  // inconclusive, is left out of Reproduction and Evidence (it stays in Affected, and in the JSON and HTML reports)
  const validatedOnly = VALIDATED_EVIDENCE_ONLY.has(title);
  const shown = validatedOnly ? g.issues.filter(i => !unvalidated(i)) : g.issues;
  const supporting = validatedOnly ? g.evidence.filter(i => !unvalidated(i)) : g.evidence;
  const left = g.issues.length - shown.length + g.evidence.length - supporting.length;
  const instances = shown.slice(0, MAX_INSTANCES).map(i => {
    const head = `- **${i.id}** at ${details(i, ctx)}${accepted(i)}: ${text(i.description, ctx)}`;
    return i.sample ? `${head}\n\n${codeBlock(ctx.scrub(i.sample), language(i.file))}` : head;
  });
  const examples = ids.flatMap(id => {
    const example = remediationOf(id)?.example;
    return example ? [`- **Illustrative implementation pattern (${id}):**\n\n${codeBlock(example, exampleLanguage(example))}`] : [];
  });

  // references: the CWE, each check's own guidance with the scenarios it supports, then Electron's security guidance.
  // Each is a list item: its title, then the address on its own line.
  const reference = (name, url) => `- ${name}\n\n  ${url}`;
  const cweUrl = `https://cwe.mitre.org/data/definitions/${/^CWE-(\d+)/.exec(cwe)?.[1]}.html`;
  const references = new Map();
  for (const v of variations) {
    for (const url of unique(v.issues.map(i => i.shortenedURL)).filter(url => /^https:\/\//i.test(url) && url !== cweUrl)) {
      const entry = references.get(url) || { labels: [], ids: [] };
      entry.labels.push(v.label);
      entry.ids.push(...v.issues.filter(i => i.shortenedURL === url).map(i => i.id));
      references.set(url, entry);
    }
  }
  const guidance = [...references].map(([url, entry]) => reference(`${unique(entry.labels).join(', ')} (${unique(entry.ids).join(', ')})`, url));

  const lines = [`---\n${front}\n---`, `# ${title}`,
    '## Issue Description', (introductions[title] || about).replaceAll('{app}', () => app),
    ...variations.map(v => `- **${v.label}.** ${v.description}`),
    ...notes('about'),
    '## Affected', `The scan identified the following locations or components in ${app}:`,
    ...places.slice(0, MAX_LOCATIONS), ...(places.length > MAX_LOCATIONS ? [`- …and ${places.length - MAX_LOCATIONS} more.`] : []),
    '## Implication',
    ...variations.map(v => `- **${v.label}.** ${v.implication}`),
    ...(g.rating.consequence === 'N/A' ? ['This hardening observation does not, by itself, establish an exploitable application vulnerability.'] : []),
    ...notes('impact'), ...notes('reachability'),
    '## Reproduction and Evidence',
    `The following evidence was recorded for ${app}. Static observations identify code or configuration; a runtime confirmation is stated explicitly where available.`,
    ...noteValues(g.issues, 'preconditions').map(value => `- **Precondition:** ${text(value, ctx)}`),
    ...noteValues(g.issues, 'steps').map(value => `- **Reproduction step:** ${text(value, ctx)}`),
    ...instances,
    ...(shown.length > MAX_INSTANCES ? [`- …and ${shown.length - MAX_INSTANCES} further instances; see the affected list or the full HTML/JSON report.`] : []),
    ...(validatedOnly && !shown.length && !supporting.length ? [`No instance of this finding was validated at runtime. The locations are listed under Affected, and every observation is in the HTML and JSON reports.`] : []),
    ...(shown.length || supporting.length ? ['**Validation results and recorded facts (all instances):**'] : []),
    ...shown.map(i => recordedEvidence(i, ctx)),
    ...supporting.map(i => `- Supporting observation: ${text(i.description, ctx)}\n\n${recordedEvidence(i, ctx)}`),
    ...(validatedOnly && left && (shown.length || supporting.length) ? [`${left} observation${left === 1 ? '' : 's'} not validated at runtime, or with an inconclusive result, ${left === 1 ? 'is' : 'are'} not listed here; ${left === 1 ? 'it is' : 'they are'} in the HTML and JSON reports.`] : []),
    '**Validation steps to perform (instructions, not recorded results):**',
    ...variations.map(v => `- **How to confirm — ${v.label}:** ${v.evidence}`),
    ...noteValues(g.issues, 'confirm').map(value => `- **How to confirm:** ${text(value, ctx)}`),
    ...ids.filter(id => validationHint(id)).map(id => `- **${text(id, ctx)}:** ${validationHint(id)}`),
    ...(COMMANDS[title] ? [`- **Validation command:** ${codeSpan(COMMANDS[title])}`] : []),
    '## Recommendations', recommendation,
    ...variations.map(v => `- **${v.label}:** ${v.recommendation}`), ...notes('recommendation'),
    ...examples,
    '## References', reference(cwe, cweUrl), ...guidance];
  if (!references.has('https://www.electronjs.org/docs/latest/tutorial/security'))
    lines.push(reference('Electron security guidance', 'https://www.electronjs.org/docs/latest/tutorial/security'));
  if (title === 'Microsoft Word Integration') lines.push(reference('Microsoft guidance on Protected View', 'https://learn.microsoft.com/en-us/office/troubleshoot/word/office-file-opens-in-protected-view'));
  // consecutive list items stay one list; everything else is a paragraph of its own
  return lines.reduce((out, line) => out + (out && out.split('\n').at(-1).startsWith('- ') && line.startsWith('- ') ? '\n' : '\n\n') + line, '').trim();
}

// characters Windows refuses in a file name, and control characters
const UNSAFE_NAME = /[<>:"/\\|?*\x00-\x1f]/g; // eslint-disable-line no-control-regex

/** A finding's file name: its title, without the characters Windows refuses in a name. */
export function findingFileName(title) {
  const name = String(title).replace(UNSAFE_NAME, '-').replace(/[. ]+$/, '').trim();
  return `${name || 'Finding'}.md`;
}

const COVERAGE_TITLE = 'Validation Coverage and Test Outcomes';
function coverageDocument(issues, ctx) {
  const records = issues.filter(i => /COVERAGE/.test(i.id) || /^RUNTIME_CAMPAIGN_(CASE|RESTORE|CLEANUP)$/.test(i.id) || /^RUNTIME_DOCX_/.test(i.id));
  if (!records.length) return undefined;
  const front = YAML.stringify({ Title: COVERAGE_TITLE, GeneratedBy: 'Electronegativity', ReportType: 'Validation coverage' }, { lineWidth: 0 }).trimEnd();
  return `---\n${front}\n---\n\n# ${COVERAGE_TITLE}\n\nThese are test outcomes and coverage limitations, not additional vulnerability findings. Acceptance, opening a view and absence of a signal do not prove execution or safety. Restore and cleanup warnings describe the test state.\n\n${records.map(i => `- ${text(i.description, ctx)}\n\n${recordedEvidence(i, ctx)}`).join('\n\n')}\n`;
}

/**
 * One Markdown document per finding, plus a coverage document when test outcomes exist: [{ title, file, content }]. meta.dir is
 * the folder the files go in (links to other reports are relative to it); meta.root the scanned folder.
 */
export function renderClientFindings(issues, meta = {}) {
  const all = [...issues, ...(meta.suppressed || [])];
  const findings = groupClientFindings(all).map(g => {
    const file = findingFileName(g.definition[0]);
    const ctx = context({ ...meta, outputFile: meta.dir ? path.join(meta.dir, file) : meta.outputFile });
    return { title: g.definition[0], file, content: `${renderGroup(g, ctx)}\n` };
  });
  const file = findingFileName(COVERAGE_TITLE);
  const coverage = coverageDocument(all, context({ ...meta, outputFile: meta.dir ? path.join(meta.dir, file) : meta.outputFile }));
  if (coverage) findings.push({ title: COVERAGE_TITLE, file, content: coverage });
  return findings;
}

// the client deliverables of a run: the findings and the components workbook they refer to
export const MARKDOWN_FOLDER = 'reports';

/**
 * A finding file's parts: its header fields (Title, Consequence, Likelihood, Notes) and its sections by heading, each as
 * written. Text before the first section heading (the # title) is not a section.
 */
export function parseFinding(content) {
  const text = String(content).replace(/\r\n?/g, '\n');
  const header = text.match(/^---\n([\s\S]*?)\n---(?:\n|$)/);
  let front;
  try {
    front = header ? YAML.parse(header[1]) || {} : {};
  } catch {
    front = {};
  }
  const body = header ? text.slice(header[0].length) : text;
  const sections = {};
  const parts = body.split(/^## (.+)$/m);
  for (let i = 1; i < parts.length; i += 2) sections[parts[i].trim()] = parts[i + 1].trim();
  return { front, sections };
}

// the same text, however an editor saved it: line endings, trailing spaces and blank lines don't count as edits
const normalized = (value) => String(value ?? '').replace(/\r\n?/g, '\n').split('\n').map(line => line.trimEnd()).join('\n').replace(/\n{3,}/g, '\n\n').trim();
const digest = (value) => crypto.createHash('sha256').update(normalized(value)).digest('hex').slice(0, 16);

/** Fingerprints of a finding file's rating, notes and each section, to tell later edits from what the tool wrote. */
export function findingFingerprints(content) {
  const { front, sections } = parseFinding(content);
  return {
    title: front.Title,
    rating: digest(`${front.Consequence ?? ''}|${front.Likelihood ?? ''}`),
    notes: digest(JSON.stringify(front.Notes ?? [])),
    sections: Object.fromEntries(Object.entries(sections).map(([heading, text]) => [heading, digest(text)])),
  };
}
export const sectionDigest = digest;
// a finding file this report wrote: an earlier run's, replaced by this one's (other files in the folder are left alone)
const isFindingFile = (file) => {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const header = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
    if (!header) return false;
    const meta = YAML.parse(header[1]);
    if (!meta?.Title || findingFileName(meta.Title) !== path.basename(file)) return false;
    if (meta.GeneratedBy === 'Electronegativity') return true;
    // A user's arbitrary Title front matter is not evidence of report ownership.
    return [...definitions, other].some(d => d[0] === meta.Title) &&
      ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References']
        .every(heading => content.includes(`\n## ${heading}\n`));
  } catch {
    return false;
  }
};

/**
 * Writes the client findings into <folder>/reports, one file per finding named after its title, replacing the finding
 * files an earlier run left there. Returns the files written.
 */
export function writeClientMarkdown(folder, issues, meta = {}, subfolder = MARKDOWN_FOLDER) {
  const dir = path.join(folder, subfolder);
  fs.mkdirSync(dir, { recursive: true });
  const findings = renderClientFindings(issues, { ...meta, dir, reportRoot: folder });
  const previous = fs.readdirSync(dir).filter(name => /\.md$/i.test(name) && isFindingFile(path.join(dir, name)));
  for (const finding of findings) {
    const file = path.join(dir, finding.file);
    if (fs.existsSync(file) && !isFindingFile(file)) throw new Error(`Refusing to overwrite a Markdown file not owned by this report: ${file}`);
  }
  const files = findings.map(finding => {
    const file = path.join(dir, finding.file);
    fs.writeFileSync(file, finding.content);
    return file;
  });
  const current = new Set(findings.map(f => f.file));
  for (const name of previous) if (!current.has(name)) fs.rmSync(path.join(dir, name));
  return files;
}

/**
 * The findings of several runs of one app (the static scan, then each watch session, which scans the code again), each
 * once, preserving validation history, evidence and screenshots across sessions. Returns { reported, suppressed }.
 */
export function combineRuns(runs) {
  const key = (i) => [i.id, i.file, i.location?.line, i.location?.column, i.description, i.sample,
    i.properties?.campaignId, i.properties?.case, i.properties?.slot, i.properties?.field, i.properties?.webContents].join('\u0000');
  const merge = (lists) => {
    const byKey = new Map();
    for (const list of lists) for (const issue of list || []) {
      const earlier = byKey.get(key(issue));
      byKey.set(key(issue), earlier ? mergeFindingEvidence(earlier, issue) : issue);
    }
    return byKey;
  };
  const suppressed = merge(runs.map(r => r.suppressed));
  const allReported = merge(runs.map(r => r.reported));
  for (const [k, issue] of suppressed) if (allReported.has(k)) suppressed.set(k, mergeFindingEvidence(allReported.get(k), issue));
  const reported = [...allReported].filter(([k]) => !suppressed.has(k)).map(([, issue]) => issue);
  return { reported, suppressed: [...suppressed.values()] };
}

/**
 * The client findings as one document (several YAML headers in a row). Suppressed findings stay visible as accepted
 * risks. meta.root is the scanned folder, which paths are shown relative to.
 */
export function renderClientMarkdown(issues, meta = {}) {
  const ctx = context(meta);
  const groups = groupClientFindings([...issues, ...(meta.suppressed || [])]);
  const coverage = coverageDocument([...issues, ...(meta.suppressed || [])], ctx);
  const findings = groups.length ? groups.map(g => renderGroup(g, ctx)).join('\n\n') : `No reportable findings were identified in ${text(ctx.app, ctx)}.`;
  return findings + (coverage ? `\n\n${coverage}` : '\n');
}
