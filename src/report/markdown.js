// Client-facing findings, grouped by the security problem rather than by scanner check.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import YAML from 'yaml';
import { consequenceOf, interactionOf, validationHint } from '../finder/consequences.js';
import { remediationOf } from '../finder/remediation.js';
import { matchingVariations } from './markdown_variations.js';
import { executionConfirmed, mergeFindingEvidence, validationResults } from '../finder/validation.js';
import { OUTDATED_TITLE, outdatedSections } from './markdown_outdated.js';
import { LEADS, NOTES, runtimeFact, staticFact, referenceTitle } from './markdown_style.js';
import { CLIENT_LABELS } from './markdown_client_copy.js';

const definitions = [
  ['Insufficient Renderer Process Isolation', /^(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX|REMOTE_MODULE|AFFINITY|PRELOAD|HTTP_RESOURCES_WITH_NODE_INTEGRATION|RUNTIME_(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX)|RUNTIME_CAMPAIGN_(NODE|ELECTRON|FS_READ)$)/, 'Untrusted content may gain access to privileged application capabilities.', 'Isolate renderers, disable Node integration and keep the sandbox enabled.', 'CWE-653: Improper Isolation or Compartmentalization'],
  ['Browser Security Controls Disabled', /^(WEB_SECURITY|INSECURE_CONTENT|EXPERIMENTAL_FEATURES|BLINK_FEATURES|WEBGL|WEBSQL|PLUGINS|NAVIGATE_ON_DRAG_DROP|CUSTOM_ARGUMENTS|SECURITY_WARNINGS_DISABLED|SECUREKEYBOARDENTRY|RUNTIME_WEB_SECURITY)/, 'Disabled browser safeguards expand what page content can do.', 'Restore Chromium defaults and enable only capabilities that are essential.', 'CWE-693: Protection Mechanism Failure'],
  ['Privileged Functionality Exposed to Web Content', /^(CONTEXT_BRIDGE_EXPOSURE|RUNTIME_PRELOAD_FOREIGN_ORIGIN|WINDOW_SESSION|RUNTIME_WINDOW_SESSION)/, 'Untrusted pages may reach privileged APIs or share a trusted session.', 'Expose narrow preload APIs and separate sessions by trust level.', 'CWE-749: Exposed Dangerous Method or Function'],
  ['Insufficient Validation of Inter-Process Messages', /^(IPC_SENDER_VALIDATION|IPC_HANDLER|IPC_FILE_ACCESS|IPC_CHANNEL_MAP|RUNTIME_MARKER_IPC)/, 'Renderer messages can reach main-process operations without adequate checks.', 'Validate the sender, arguments and allowed operations in every handler.', 'CWE-20: Improper Input Validation'],
  ['Unvalidated URLs and Files Passed to the Operating System', /^(OPEN_EXTERNAL|OPEN_PATH|SHOWITEMINFOLDER|WRITE_SHORTCUT|DOWNLOAD|RUNTIME_(OPEN_EXTERNAL|OPEN_PATH)|RUNTIME_MARKER_(OPEN_EXTERNAL|OPEN_PATH))/, 'Untrusted URLs or file paths may be opened by the operating system.', 'Allowlist URL schemes and hosts, and constrain file paths before opening them.', 'CWE-73: External Control of File Name or Path'],
  ['Command or Code Execution from Variable Input', /^(COMMAND_INJECTION|DANGEROUS_FUNCTIONS|DYNAMIC_MODULE|RUNTIME_MARKER_(COMMAND|MODULE))/, 'Untrusted data may reach command or code execution.', 'Avoid command-line construction and pass validated arguments to safe APIs.', 'CWE-78: Improper Neutralization of Special Elements used in an OS Command'],
  ['Insecure Microsoft Word Integration', /^WORD_LAUNCH/, 'Opening documents in Microsoft Word can expose users to unsafe document content or command construction.', 'Validate document paths and preserve Mark-of-the-Web metadata before opening files.', 'CWE-73: External Control of File Name or Path'],
  ['Insecure Handling of Deep Links and File Associations', /^(FILE_HANDLER|PROTOCOL_HANDLER|PROTOCOL_PRIVILEGES|INSTALLER_FILE_HANDLER|FILE_PROTOCOL)/, 'External links and files can enter privileged application flows.', 'Parse deep links and file associations as untrusted input and allow only known actions.', 'CWE-20: Improper Input Validation'],
  ['Insufficient Navigation and New Window Restrictions', /^(LIMIT_NAVIGATION|UNTRUSTED_LOAD_URL|WINDOW_OPEN_HANDLER|NAVIGATION_REDIRECT|AUXCLICK|ALLOWPOPUPS|WEBVIEW|IFRAME_SANDBOX|RUNTIME_(NAVIGATION|NEW_WINDOW|REDIRECT|WEBVIEW)|RUNTIME_MARKER_(NAVIGATION|NEW_WINDOW))/, 'Untrusted navigation or new windows may retain application privileges.', 'Deny navigation and new windows by default, then allowlist intended destinations.', 'CWE-601: URL Redirection to Untrusted Site'],
  ['Permissive Browser Permission Handling', /^(PERMISSION_REQUEST_HANDLER|RUNTIME_PERMISSION|RUNTIME_PERMISSION_CHECK)/, 'Pages may obtain capabilities without an explicit application decision.', 'Install request and check handlers that deny permissions by default.', 'CWE-862: Missing Authorization'],
  ['Cross-Site Scripting in Content Rendering', /^(XSS_SINK|RICH_TEXT_EDITOR|SANITIZER_CONFIG|ANGULAR|RUNTIME_DOM_INJECTION|RUNTIME_MARKER|RUNTIME_HTML_ENDPOINT|RUNTIME_(ACTIVE_SCRIPT|CAMPAIGN_SCRIPT)|TRAFFIC_WS_HTML_MESSAGE|TRAFFIC_REFLECTED_INPUT)/, 'Untrusted content may be rendered as executable markup.', 'Render text as text; sanitise allowed HTML before insertion into the page.', 'CWE-79: Improper Neutralization of Input During Web Page Generation'],
  ['Missing or Insufficient Content Security Policy', /^(CSP$|CSP_DIRECTIVES|RUNTIME_CSP|RUNTIME_CAMPAIGN_EVAL$)/, 'A missing or permissive policy reduces protection against script injection.', 'Ship a restrictive Content Security Policy for every renderer.', 'CWE-693: Protection Mechanism Failure'],
  ['Insecure Processing of Untrusted Documents', /^DOCUMENT_PIPELINE/, 'Documents enter parsers or renderers that need strict isolation.', 'Validate file types and parse untrusted documents in a restricted context.', 'CWE-20: Improper Input Validation'],
  ['Insecure Electron Fuse Configuration', /^(FUSES|PACKAGED_FUSES)/, 'Packaged Electron fuses leave unnecessary privileges available.', 'Set secure fuses at package time and verify the packaged executable.', 'CWE-693: Protection Mechanism Failure'],
  ['Application Code Not Protected Against Tampering or Disclosure', /^(ASAR_INTEGRITY|SOURCE_MAP_SHIPPED)/, 'Packaged application code may be exposed or changed without detection.', 'Remove production source maps and enable asar integrity with the associated fuses.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Missing Code Signing or Exploit Mitigations', /^(CODE_SIGNING|BINARY_HARDENING)/, 'The executable lacks a signing or binary hardening safeguard.', 'Sign releases and enable platform exploit mitigations.', 'CWE-693: Protection Mechanism Failure'],
  ['Insecure Software Update Mechanism', /^UPDATE_SECURITY/, 'The update channel may install software without sufficient verification.', 'Use an authenticated update channel and verify publisher signatures.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Debugging Features Enabled in Production', /^(DEVTOOLS|DEVELOPMENT_CODE|DEBUG_LOGGING|RUNTIME_SECRET_IN_CONSOLE|RUNTIME_UNCAUGHT_EXCEPTION)/, 'Development features can disclose information or expand the attack surface.', 'Remove debug facilities and sensitive logs from production builds.', 'CWE-489: Active Debug Code'],
  ['Hard-coded Secrets in the Application Package', /^HARDCODED_SECRET/, 'Secrets shipped in the application package can be recovered by anyone with the package.', 'Remove and rotate embedded secrets; keep server credentials on the server.', 'CWE-798: Use of Hard-coded Credentials'],
  ['Sensitive Data Stored Without Adequate Protection', /^(STORAGE|SECRET_FILE_WRITE|ELECTRON_STORE_ENCRYPTION|PLAINTEXT_SECRETS)/, 'Sensitive data may be recoverable from local storage.', 'Use the operating system credential store or safeStorage for secrets.', 'CWE-312: Cleartext Storage of Sensitive Information'],
  ['Certificate Pinning Not Implemented', /^CERTIFICATE_PINNING/, 'Backend connections trust any certificate the operating system trusts.', 'Pin backend certificates or keys where the threat model requires it.', 'CWE-295: Improper Certificate Validation'],
  ['Insecure Network Transport and Certificate Validation', /^(HTTP_RESOURCES|RUNTIME_INSECURE_LOAD|TRAFFIC_(CLEARTEXT_HTTP|WS_CLEARTEXT|BASIC_AUTH|INSECURE_COOKIE)|COOKIE_FLAGS|CERTIFICATE|NODE_TLS_REJECT_UNAUTHORIZED|RUNTIME_CERTIFICATE_ERROR)/, 'Traffic or credentials may be exposed in transit.', 'Use HTTPS and WSS, validate certificates and set secure cookie attributes.', 'CWE-319: Cleartext Transmission of Sensitive Information'],
  ['Sensitive Data Exposed in Network Traffic', /^(TRAFFIC_(SECRET_IN_URL|SECRET_IN_RESPONSE|WS_SECRET|AUTH_TO_THIRD_PARTY|USER_INPUT_TO_THIRD_PARTY))/, 'Network requests may expose credentials or user data to unintended recipients.', 'Restrict data sent to each host and remove secrets from URLs and responses.', 'CWE-201: Insertion of Sensitive Information Into Sent Data'],
  // the Electron runtime and third-party components, in one finding that refers to the components workbook
  [OUTDATED_TITLE, /^(AVAILABLE_SECURITY_FIXES|UNSUPPORTED_VERSION|CHROMIUM_ADVISORIES|DEPENDENCY_VULNERABILITIES|END_OF_LIFE_LIBRARY)/, 'The application uses outdated software components.', 'Upgrade or replace each affected component.', 'CWE-1104: Use of Unmaintained Third Party Components'],
  ['Known Malicious Software Package', /^MALICIOUS_DEPENDENCY/, 'A known malicious package was detected in the dependency inventory.', 'Remove the package immediately and rotate potentially exposed secrets.', 'CWE-506: Embedded Malicious Code'],
];

const other = ['Additional Security Observations', null, 'Additional scanner observations require assessment.', 'Investigate the listed observations and apply the linked guidance.', 'CWE-693: Protection Mechanism Failure'];
// (PRELOAD_JS_CHECK is informational with context isolation, reported without: the preload then shares the page's world)
const evidenceOnly = /^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|IPC_RENDERER_CHANNEL|RUNTIME_IPC$|RUNTIME_MARKER_SENT|CREDENTIAL_ACCESS|DEPENDENCY_INVENTORY|ELECTRON_VERSION)/;
const observations = new Set(['SOURCE_MAP_SHIPPED', 'STORAGE_CACHED_RESPONSES', 'CERTIFICATE_PINNING', 'WORD_LAUNCH']);
// findings whose Reproduction and Evidence lists only validated instances
const VALIDATED_EVIDENCE_ONLY = new Set(['Cross-Site Scripting in Content Rendering']);
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
// commands that check a finding by hand, per group
const COMMANDS = {
  'Insecure Electron Fuse Configuration': 'npx @electron/fuses read --app "<exe>"',
  'Application Code Not Protected Against Tampering or Disclosure': 'npx @electron/asar extract app.asar out',
  'Insecure Microsoft Word Integration': 'Get-Item <doc> -Stream Zone.Identifier',
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
  if (['RUNTIME_OPEN_PATH', 'RUNTIME_MARKER_OPEN_PATH'].includes(id) && /\.(?:docx?|rtf)\b/i.test(i.description || '')) return definitionOf('Insecure Microsoft Word Integration');
  // the switch that turns certificate validation off belongs with the certificate findings
  if (id === 'CUSTOM_ARGUMENTS' && /ignore-certificate-errors/i.test(i.description || '')) return definitionOf('Insecure Network Transport and Certificate Validation');
  return definitions.find(g => g[1].test(id)) || other;
}

function evidenceGroupOf(i) {
  const id = normalId(i.id);
  if (id === 'RUNTIME_CSP_VIOLATION') return 'Missing or Insufficient Content Security Policy';
  if (/^RUNTIME_DOCX_/.test(id)) return 'Insecure Processing of Untrusted Documents';
  if (id === 'RUNTIME_WINDOW_COVERAGE') return 'Insufficient Renderer Process Isolation';
  if (/^RUNTIME_(CAMPAIGN|ACTIVE|ENTRY)_COVERAGE$/.test(id) || /^RUNTIME_CAMPAIGN_(RESTORE|CLEANUP)$/.test(id))
    return ['Cross-Site Scripting in Content Rendering', 'Insufficient Renderer Process Isolation', 'Missing or Insufficient Content Security Policy', 'Insecure Processing of Untrusted Documents'];
  if (/^RUNTIME_CAMPAIGN_/.test(id)) {
    const name = i.properties?.case || '';
    if (name.startsWith('nav-')) return 'Insufficient Navigation and New Window Restrictions';
    if (['node', 'electron', 'fs-read'].includes(name)) return ['Insufficient Renderer Process Isolation', 'Cross-Site Scripting in Content Rendering'];
    if (name === 'eval') return ['Missing or Insufficient Content Security Policy', 'Cross-Site Scripting in Content Rendering'];
    return 'Cross-Site Scripting in Content Rendering';
  }
  if (/^RUNTIME_MARKER_(NAVIGATION|NEW_WINDOW)$/.test(id)) return 'Insufficient Navigation and New Window Restrictions';
  if (/^RUNTIME_MARKER_OPEN_(PATH|EXTERNAL)$/.test(id)) return groupOf(i)[0];
  if (/^RUNTIME_MARKER_(COMMAND|MODULE)$/.test(id)) return 'Command or Code Execution from Variable Input';
  if (id === 'CSP') return 'Missing or Insufficient Content Security Policy';
  if (id === 'NAVIGATION_REDIRECT') return 'Insufficient Navigation and New Window Restrictions';
  if (/^(RUNTIME_MARKER|RUNTIME_MARKER_SENT)$/.test(id)) return 'Cross-Site Scripting in Content Rendering';
  if (/^(IPC_HANDLER|IPC_CHANNEL_MAP|IPC_RENDERER_CHANNEL|RUNTIME_IPC|RUNTIME_MARKER_IPC)$/.test(id)) return 'Insufficient Validation of Inter-Process Messages';
  if (/^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|PRELOAD)$/.test(id)) return 'Insufficient Renderer Process Isolation';
  if (id === 'DEPENDENCY_INVENTORY' || id === 'ELECTRON_VERSION') return OUTDATED_TITLE;
  if (id === 'CREDENTIAL_ACCESS') return 'Sensitive Data Stored Without Adequate Protection';
  if (id === 'DOCUMENT_PIPELINE') return 'Insecure Processing of Untrusted Documents';
  return undefined;
}

export function ratingOf(i, title) {
  const id = normalId(i.id);
  const severity = nameOf(i.severity);
  // outdated components are rated Informational: the tool does not exploit the published vulnerabilities, and a tester
  // who does raises the rating by hand
  if (severity === 'INFORMATIONAL' || title === OUTDATED_TITLE ||
      title === 'Missing Code Signing or Exploit Mitigations' && severity === 'LOW') return { consequence: 'N/A', likelihood: 'N/A' };
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
 * packaged app's install folder) and the home and temporary folders, which never appear in the report.
 */
function context(meta) {
  const root = meta.root ? path.resolve(meta.root) : undefined;
  const bases = root ? [root] : [];
  if (root && /[\\/]resources[\\/]app(\.asar)?$/i.test(root)) bases.push(path.dirname(path.dirname(root)));
  const home = os.homedir();
  const temp = os.tmpdir();
  // a folder as a file URL (encoded or not) and as a path written with either slash
  const forms = (folder) => {
    const url = pathToFileURL(folder).href;
    let decoded = url;
    try {
      decoded = decodeURI(url);
    } catch { /* keep the encoded form */ }
    return unique([url, decoded, folder, folder.replace(/\\/g, '/'), folder.replace(/\//g, '\\')]);
  };
  const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const within = (folder) => new RegExp(forms(folder).map(form => `${escape(form)}(?:[\\\\/]|(?![\\w.-]))`).join('|'), 'g');
  const baseForms = bases.map(base => ({ pattern: within(base), name: path.basename(base) }));
  // a file in the temporary folder: what follows the tool's own folder there (a downloaded copy of a server's script)
  const tempPattern = new RegExp(forms(temp).map(form => `${escape(form)}[\\\\/](?:electronegativity-[^\\\\/\\s'"]*[\\\\/])?`).join('|'), 'g');
  const scrub = (value) => {
    let out = String(value ?? '');
    for (const { pattern, name } of baseForms) out = out.replace(pattern, (match) => /[\\/]$/.test(match) ? '' : name);
    out = out.replace(tempPattern, '');
    return home && home.length > 1 ? out.split(home).join('~') : out;
  };
  const packaged = !!root && /[\\/]resources[\\/]app\.asar$/i.test(root);
  return { app: meta.app?.name || 'the application', bases, scrub, packaged, outputFile: meta.outputFile, dependencies: meta.dependencies,
    reportRoot: meta.reportRoot || (meta.outputFile && path.dirname(path.resolve(meta.outputFile))), outputs: meta.outputs || [] };
}

function shownFile(file, ctx) {
  let value = String(file);
  if (/^file:\/\//i.test(value)) {
    try {
      value = fileURLToPath(value);
    } catch { /* not a local file URL */ }
  }
  if (!path.isAbsolute(value)) return ctx.scrub(value);
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
  return cut ? `${block}\n\n${indent}(Excerpt: a further ${cut} characters are not shown.)` : block;
}

const isRuntime = i => /^RUNTIME_|^TRAFFIC_/.test(i.id);
// the file and line of a finding, or undefined for one that has none (a runtime observation, an application-wide setting)
function place(i, ctx) {
  if (!i.file || i.file === 'N/A' || i.file === 'runtime') return undefined;
  return `${shownFile(i.file, ctx)}${i.location?.line ? `:${i.location.line}` : ''}`;
}
function location(i, ctx) {
  const where = place(i, ctx);
  if (where) return codeSpan(where);
  return isRuntime(i) ? `${text(ctx.app, ctx)}, observed during testing` : `${text(ctx.app, ctx)} (application-wide)`;
}
function details(i, ctx) {
  const p = i.properties || {};
  const pkg = scalar(p.package) || scalar(p.name);
  return [location(i, ctx), scalar(p.url) && codeSpan(ctx.scrub(p.url)), scalar(p.window) && text(p.window, ctx), scalar(p.channel) && `channel ${codeSpan(p.channel)}`,
    scalar(p.fuse) && `fuse ${codeSpan(`${p.fuse}=${typeof p.value === 'boolean' ? p.value : scalar(p.value) ?? 'unknown'}`)}`, scalar(p.cookie) && `cookie ${codeSpan(p.cookie)}`, scalar(p.host) && codeSpan(p.host),
    pkg && codeSpan(`${pkg}${scalar(p.version) ? `@${p.version}` : ''}`), Array.isArray(p.advisories) && p.advisories.length && `${p.advisories.length} advisories`].filter(Boolean).join(' — ');
}

// a screenshot next to the report: its path from the finding; undefined for one elsewhere
function screenshotPath(file, ctx) {
  if (!ctx.outputFile || !path.isAbsolute(file)) return undefined;
  const relative = path.relative(path.dirname(path.resolve(ctx.outputFile)), file);
  const within = path.relative(path.resolve(ctx.reportRoot), file);
  if (within === '..' || within.startsWith(`..${path.sep}`) || path.isAbsolute(within)) return undefined;
  return linkTarget(relative.split(path.sep).join('/'));
}
// a screenshot next to the report is linked; one elsewhere is named
function screenshot(file, ctx) {
  const target = screenshotPath(file, ctx);
  return target ? `[${text(path.basename(file), ctx)}](${target})` : codeSpan(ctx.scrub(file));
}
const screenshotsOf = i => unique([i.properties?.screenshot, ...strings(i.properties?.screenshots)]).filter(f => typeof f === 'string');
const screenshotOf = (i, ctx) => screenshotsOf(i).map(f => `; screenshot ${screenshot(f, ctx)}`).join('');

// Facts stay with their owning check. Arbitrary properties may contain credentials, so only known evidence fields are shown.
function recordedEvidence(i, ctx) {
  const p = i.properties || {};
  const lines = [`- **${text(i.id, ctx)}** at ${location(i, ctx)}${i.session ? `; session ${text(i.session, ctx)}` : ''}${screenshotOf(i, ctx)}`];
  const results = validationResults(i);
  for (const r of results) {
    lines.push(`  - Validation: **${text(r.status, ctx)}**${r.scope ? ` (${text(r.scope, ctx)})` : ''}${r.session ? `; session ${text(r.session, ctx)}` : ''}${r.text ? ` — ${text(r.text, ctx)}` : ''}`);
    for (const value of strings(r.evidence)) lines.push(`    - Evidence: ${text(value, ctx)}`);
  }
  if (!results.length) lines.push(`  - Validation: ${isConfirmed(i) ? 'script execution or tested capability recorded; wider exploitability unverified' : isRuntime(i) ? 'runtime observation; exploitability unverified' : 'not run; static or artifact observation only'}`);
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

// what an accepted risk is recorded with, for the finding's Notes
function acceptedRisk(s, label, ctx) {
  const { reason, owner, expires } = s.suppression;
  const where = place(s, ctx);
  return `Accepted risk: ${label}${where ? ` at ${where}` : ''}. ${reason ? ctx.scrub(reason).replace(/\s+/g, ' ').trim() : 'No reason was recorded.'}${owner ? ` Owner: ${ctx.scrub(owner)}.` : ''}${expires ? ` Expires: ${ctx.scrub(expires)}.` : ''}`;
}

// why the finding has its rating, and what testing did and did not establish: for the tester, not the client
function proseNotes(g, ctx) {
  const i = g.basis;
  if (g.definition[0] === OUTDATED_TITLE) return ['Rated Informational: the known vulnerabilities of the listed components were not exploited during the engagement.',
    ...g.issues.filter(x => x.suppression).map(s => `Accepted risk — ${s.id} at ${text(place(s, ctx) || 'application-wide', ctx)}. ${s.suppression.reason ? text(s.suppression.reason, ctx) : 'No reason supplied.'}`)];
  const status = isConfirmed(i) ? 'runtime evidence recorded' : isRuntime(i) ? 'observed at runtime; exploitability not established' : 'runtime exploitability not established';
  const notes = [`Rating basis: ${i.id} at ${text(place(i, ctx) || 'no single location', ctx)}; scanner severity ${nameOf(i.severity)}, confidence ${nameOf(i.confidence)}; ${status}.`];
  notes.push('The scenarios are conditional where testing did not establish input control, reachability or the affected trust boundary. Impact is limited to the circumstances supported by the evidence.');
  const open = g.issues.filter(issue => issue.manualReview && !isConfirmed(issue) && !issue.suppression);
  if (open.length) notes.push(`${open.length} instance${open.length === 1 ? '' : 's'} require${open.length === 1 ? 's' : ''} reachability or configuration review; exploitation has not been established for those instances.`);
  if (g.definition[0] === 'Sensitive Data Exposed in Network Traffic') notes.push('Establish ownership of each destination before characterising a transfer as third-party disclosure.');
  if (g.definition[0] === 'Insecure Microsoft Word Integration') notes.push('The Protected View scenario applies only where document provenance is lost in the actual opening workflow.');
  if (g.definition[0] === 'Insufficient Validation of Inter-Process Messages') notes.push('Channel-use conclusions depend on the shipped renderer and representative runtime coverage.');
  if (g.accepted) notes.push('Every instance of this finding is an accepted risk; the rating is that of the accepted instances.');
  else if (g.issues.some(x => x.suppression)) notes.push('Accepted risks are listed with this finding but do not set its rating.');
  for (const s of g.issues.filter(x => x.suppression)) {
    const { reason, owner, expires } = s.suppression;
    notes.push(`Accepted risk — ${s.id} at ${text(place(s, ctx) || 'application-wide', ctx)}. ${reason ? text(reason, ctx) : 'No reason supplied.'}${owner ? ` Owner ${text(owner, ctx)}.` : ''}${expires ? ` Expires ${text(expires, ctx)}.` : ''}`);
  }
  return notes;
}

// Markdown blocks in a row: consecutive bullets stay one list; everything else is a paragraph of its own
const joinBlocks = lines => lines.filter(line => line !== undefined && line !== '').reduce((out, line) =>
  out + (out && out.split('\n').at(-1).startsWith('- ') && line.startsWith('- ') ? '\n' : '\n\n') + line, '').trim();
// a numbered list: each item's further lines indented under its number
function numbered(items) {
  const multiline = items.some(item => item.includes('\n'));
  return items.map((item, n) => {
    const marker = `${n + 1}. `;
    return marker + item.split('\n').map((line, k) => !k || !line ? line : ' '.repeat(marker.length) + line).join('\n');
  }).join(multiline ? '\n\n' : '\n');
}
// "that A", "that A, and that B", "that A, that B, and that C"
const thatList = facts => facts.length === 1 ? `that ${facts[0]}` : `${facts.slice(0, -1).map(f => `that ${f}`).join(', ')}, and that ${facts.at(-1)}`;
// a runtime result recorded against a static finding, as client text: the confirmed and observed ones
const validatedFacts = i => unique(validationResults(i).filter(r => ['confirmed', 'observed'].includes(r.status) && r.text)
  .map(r => runtimeFact({ id: 'RUNTIME_VALIDATION', description: r.text })));
// a front matter block; empty Notes are left out
const frontMatter = (title, rating, notes) => YAML.stringify({ Title: title, GeneratedBy: 'Electronegativity', Consequence: rating.consequence,
  Likelihood: rating.likelihood, ...(notes.length ? { Notes: notes } : {}) }, { lineWidth: 0 }).trimEnd();
// how a check's instance is checked by hand, for the reproduction step of a file with no source to show
const INSPECT = {
  PACKAGED_FUSES: file => `Read the Electron fuses of ${codeSpan(file)} with ${codeSpan(`npx @electron/fuses read --app "${file}"`)}.`,
  CODE_SIGNING: file => `Check the publisher signature of ${codeSpan(file)} in PowerShell with ${codeSpan(`Get-AuthenticodeSignature "${file}"`)}.`,
  BINARY_HARDENING: file => `Inspect the exploit mitigation flags of ${codeSpan(file)}, for example with ${codeSpan(`dumpbin /headers "${file}"`)}.`,
  FUSES: file => `Review the packaging configuration in ${codeSpan(file)} and the build scripts.`,
};
// a fact sentence with text taken from the app: its Markdown and HTML syntax escaped, except in the code spans the
// sentence puts around names
const safeFact = fact => String(fact).split(/(`[^`]*`)/).map((part, n) => n % 2 ? part : part.replace(/[\\*[\]<>_]/g, '\\$&')).join('');
// one example per kind of code: the same settings object shown twice is shown once
const exampleKey = example => String(example).replace(/\s+/g, ' ').split(/[({]/)[0].trim();

// the outdated components finding: its own sections, pointing at the components workbook
function renderOutdated(g, ctx) {
  const [title, , , , cwe] = g.definition;
  const sections = outdatedSections({ app: text(ctx.app, ctx), dependencies: ctx.dependencies });
  const notes = g.issues.filter(x => x.suppression).map(s => acceptedRisk(s, 'outdated component', ctx));
  const lines = [`---\n${frontMatter(title, g.rating, notes)}\n---`, `# ${title}`,
    '## Issue Description', ...sections.description,
    '## Affected', ...sections.affected,
    '## Implication', ...sections.implication,
    '## Reproduction and Evidence', ...sections.evidence,
    '## Recommendations', ...sections.recommendations,
    '## References', ...sections.references, `- ${cwe}\n\n  https://cwe.mitre.org/data/definitions/${/^CWE-(\d+)/.exec(cwe)?.[1]}.html`];
  return joinBlocks(lines);
}

// how many reproduction steps a finding shows; the rest are named under Affected
const MAX_STEPS = 10;

/** The parts of one finding both its client document and its tester notes are written from. */
function findingParts(g, ctx) {
  const title = g.definition[0];
  const variations = matchingVariations(title, g.issues, normalId);
  const labelOf = v => CLIENT_LABELS[v.label] || 'Additional observation';
  // findings whose evidence lists only what was validated: an instance whose validation was not run, or was
  // inconclusive, is left out of Reproduction and Evidence (it stays in Affected, in the tester notes and in the JSON and
  // HTML reports)
  const validatedOnly = VALIDATED_EVIDENCE_ONLY.has(title);
  // runtime outcomes where the application refused the test: they mitigate the finding rather than show it
  const blocked = [...g.issues, ...g.evidence].filter(i => i.properties?.blocked === true);
  const shown = g.issues.filter(i => !blocked.includes(i) && (!validatedOnly || !unvalidated(i)));
  const supporting = g.evidence.filter(i => !blocked.includes(i) && isRuntime(i) && (screenshotsOf(i).length || isConfirmed(i) ||
    validationResults(i).some(r => r.status === 'confirmed')) && (!validatedOnly || !unvalidated(i)));
  return { title, variations, labelOf, validatedOnly, blocked, shown, supporting };
}

// a screenshot in a reproduction step: shown when it is next to the report, named otherwise
function image(file, ctx) {
  const target = screenshotPath(file, ctx);
  return target ? `![${text(path.basename(file), ctx)}](${target})` : `The screenshot ${codeSpan(path.basename(file))} shows the result.`;
}

function reproductionSteps(g, ctx, parts) {
  const { shown, supporting } = parts;
  const app = text(ctx.app, ctx);
  const steps = noteValues(g.issues, 'steps').map(value => text(value, ctx));
  const staticOnes = shown.filter(i => !isRuntime(i));
  // each location once, with every fact recorded there
  const locations = new Map();
  for (const i of staticOnes) {
    const key = place(i, ctx) || '';
    if (!locations.has(key)) locations.set(key, []);
    locations.get(key).push(i);
  }
  const fromArchive = ctx.packaged && staticOnes.some(i => place(i, ctx) && !/\.(exe|dll|node)$/i.test(i.file));
  if (fromArchive) steps.push(`Extract the application archive ${codeSpan('resources\\app.asar')} from the installation folder of ${app}, for example with ${codeSpan('npx @electron/asar extract "resources\\app.asar" app')}. The file paths below are relative to the extracted folder.`);
  const facts = [];
  // code shown in an earlier step is not shown again
  const shownCode = new Set();
  for (const [where, issues] of locations) {
    const first = issues[0];
    const found = unique(issues.map(i => safeFact(ctx.scrub(staticFact(i, normalId)))).filter(Boolean));
    const validated = unique(issues.flatMap(validatedFacts));
    const shows = found.length ? `This shows ${thatList(found)}.` : '';
    const during = validated.map(fact => `During testing, ${text(fact, ctx, 1000)}.`).join(' ');
    const accepted = issues.every(i => i.suppression) ? ' This instance has been accepted as a risk.' : '';
    const file = where && shownFile(first.file, ctx);
    const inspect = INSPECT[normalId(first.id)];
    const samples = unique(issues.map(i => i.sample && ctx.scrub(i.sample)));
    let step;
    if (!where) step = found.length ? `Review the configuration of ${app}, which shows ${thatList(found)}.` : `Review the configuration of ${app}.`;
    else if (inspect && !samples.length) step = `${inspect(file)} ${shows}`;
    else if (samples.length && shownCode.has(samples[0])) step = `Open ${codeSpan(file)} and review line ${first.location?.line || 1}, which holds the same code as above. ${shows}`;
    else if (samples.length) {
      shownCode.add(samples[0]);
      step = `Open ${codeSpan(file)} and review line ${first.location?.line || 1}:\n\n${codeBlock(samples[0], language(first.file), '')}\n\n${shows}`;
    }
    else step = `Open ${codeSpan(file)}${first.location?.line > 1 ? ` and review line ${first.location.line}` : ''}. ${shows}`;
    const images = unique(issues.flatMap(screenshotsOf)).map(file => image(file, ctx));
    facts.push(`${`${step.trim()}${during ? ` ${during}` : ''}${accepted}`.trim()}${images.length ? `\n\n${images.join('\n\n')}` : ''}`);
  }
  const runtime = [...shown.filter(isRuntime), ...supporting];
  const seen = new Set();
  for (const i of runtime) {
    const fact = runtimeFact(i);
    if (!fact || seen.has(fact)) continue;
    seen.add(fact);
    const images = screenshotsOf(i).map(file => image(file, ctx));
    facts.push(`During testing, ${text(fact, ctx, 1000)}.${images.length ? `\n\n${images.join('\n\n')}` : ''}`);
  }
  const room = MAX_STEPS - (fromArchive ? 1 : 0);
  steps.push(...facts.slice(0, room));
  return { steps, more: facts.length > room };
}

function renderGroup(g, ctx) {
  const [title, , , recommendation, cwe] = g.definition;
  if (title === OUTDATED_TITLE) return renderOutdated(g, ctx);
  const parts = findingParts(g, ctx);
  const { variations, labelOf, validatedOnly, blocked } = parts;
  const app = text(ctx.app, ctx);
  const notes = field => noteValues(g.issues, field).map(value => text(value, ctx));
  const accepted = g.issues.filter(x => x.suppression).map(s => acceptedRisk(s, labelOf(variations.find(v => v.issues.includes(s)) || { label: s.id }), ctx));

  // each location once, with the scenarios it supports
  const affected = new Map();
  for (const i of g.issues) {
    const where = details(i, ctx);
    const entry = affected.get(where) || { labels: [], accepted: true };
    entry.labels.push(...variations.filter(v => v.issues.includes(i)).map(labelOf));
    entry.accepted = entry.accepted && !!i.suppression;
    affected.set(where, entry);
  }
  const places = [...affected].map(([where, entry]) => `- ${where} — ${unique(entry.labels).join('; ')}${entry.accepted ? ' (accepted risk)' : ''}`);

  // the limits of testing, once; what testing confirmed or what the application blocked qualifies it
  const confirmed = parts.shown.some(isConfirmed) || parts.supporting.some(isConfirmed);
  const blockedFacts = unique(blocked.map(runtimeFact));
  const note = [confirmed ? 'This issue was confirmed during testing, as described under Reproduction and Evidence.' : '',
    NOTES[title] || 'The impact depends on whether an attacker can reach the affected functionality.',
    blockedFacts.length ? `During testing, ${blockedFacts.length === 1 ? text(blockedFacts[0], ctx) : `the application blocked some attempts: ${blockedFacts.map(fact => text(fact, ctx)).join('; ')}`}.` : '',
    g.rating.consequence === 'N/A' && !/hardening observation/.test(NOTES[title] || '') ? 'This is a hardening observation and does not, by itself, constitute an exploitable vulnerability.' : '',
  ].filter(Boolean).join(' ');

  const { steps, more } = reproductionSteps(g, ctx, parts);
  const preconditions = notes('preconditions');

  const recommendations = unique([...notes('recommendation'), ...(variations.length ? variations.map(v => v.recommendation) : [recommendation])]);
  const examples = [...new Map(unique(unique(g.issues.map(i => i.id)).map(id => remediationOf(id)?.example))
    .map(example => [exampleKey(example), example])).values()].slice(0, 2);

  // references: the CWE, the guidance of each check, then Electron's security checklist. Each is a list item: its title,
  // then the address on its own line.
  const reference = (name, url) => `- ${name}\n\n  ${url}`;
  const cweUrl = `https://cwe.mitre.org/data/definitions/${/^CWE-(\d+)/.exec(cwe)?.[1]}.html`;
  const urls = unique(variations.flatMap(v => v.issues.map(i => i.shortenedURL))).filter(url => /^https:\/\//i.test(url) && url !== cweUrl);
  const references = [reference(cwe, cweUrl)];
  const titles = new Set();
  for (const url of urls) {
    const name = referenceTitle(url);
    if (titles.has(`${name}|${url}`)) continue;
    titles.add(`${name}|${url}`);
    references.push(reference(name, url));
  }
  if (!urls.some(url => /electronjs\.org/.test(url))) references.push(reference('Electron security checklist', 'https://www.electronjs.org/docs/latest/tutorial/security'));
  if (title === 'Insecure Microsoft Word Integration') references.push(reference('Microsoft documentation: What is Protected View?', 'https://learn.microsoft.com/en-us/office/troubleshoot/word/office-file-opens-in-protected-view'));

  const lead = (LEADS[title] || 'Testing identified the following security observations in {app}.').replaceAll('{app}', () => app);
  const lines = [`---\n${frontMatter(title, g.rating, accepted)}\n---`, `# ${title}`,
    '## Issue Description', lead,
    ...notes('about'),
    ...variations.map(v => `- **${labelOf(v)}.** ${v.description}`),
    '## Affected', `The following locations in ${app} are affected:`,
    ...places.slice(0, MAX_LOCATIONS), ...(places.length > MAX_LOCATIONS ? [`- A further ${places.length - MAX_LOCATIONS} locations with the same issue.`] : []),
    '## Implication',
    ...variations.map(v => `- **${labelOf(v)}.** ${v.implication}`),
    ...notes('impact'), ...notes('reachability'),
    `*Note:* ${note}`,
    '## Reproduction and Evidence',
    ...(preconditions.length ? [`The following preconditions apply: ${preconditions.join(' ')}`] : []),
    ...(steps.length ? ['The issue can be reproduced as follows:', numbered(steps)]
      : validatedOnly ? ['No instance of this issue was validated at runtime during testing. The locations identified through review of the application code are listed under Affected.']
        : [`The locations listed under Affected were identified through review of ${app}.`]),
    ...(more ? ['Further instances are listed under Affected.'] : []),
    '## Recommendations', numbered(recommendations),
    ...(examples.length ? [`The following example${examples.length === 1 ? ' illustrates' : 's illustrate'} the recommended approach:`,
      ...examples.map(example => codeBlock(example, exampleLanguage(example), ''))] : []),
    '## References', ...references];
  return joinBlocks(lines);
}

// the tester's companion to a finding: how it was rated, every instance with its recorded facts (including those left out
// of the client document) and how to check each by hand
function testerNotesDocument(g, ctx, file) {
  const title = g.definition[0];
  const parts = title === OUTDATED_TITLE ? undefined : findingParts(g, ctx);
  const ids = unique(g.issues.map(i => i.id));
  const lines = [TESTER_NOTES_MARKER, `# ${title}: tester notes`,
    `Working notes for the finding ${codeSpan(file)}. They are not part of the client report.`,
    '## Rating basis', `Consequence: ${g.rating.consequence}. Likelihood: ${g.rating.likelihood}.`,
    ...proseNotes(g, ctx).map(value => `- ${value}`),
    '## Checks',
    ...ids.map(id => {
      const count = g.issues.filter(i => i.id === id).length;
      const consequence = consequenceOf(id)?.text;
      return `- **${text(id, ctx)}** (${count} instance${count === 1 ? '' : 's'})${consequence ? `: ${text(consequence, ctx)}` : ''}`;
    })];
  if (parts) {
    lines.push('## Scenarios', ...parts.variations.map(v => `- **${text(v.label, ctx)}** (client label: ${parts.labelOf(v)}): ${v.issues.length} instance${v.issues.length === 1 ? '' : 's'}`));
    const left = g.issues.length - parts.shown.length;
    if (parts.validatedOnly && left) lines.push(`${left} instance${left === 1 ? ' was' : 's were'} not validated at runtime, or had an inconclusive result, and ${left === 1 ? 'is' : 'are'} not listed under Reproduction and Evidence in the client finding.`);
    if (parts.blocked.length) lines.push(`${parts.blocked.length} runtime outcome${parts.blocked.length === 1 ? ' was' : 's were'} blocked by the application and ${parts.blocked.length === 1 ? 'is' : 'are'} described in the note under Implication.`);
  }
  lines.push('## Validation steps',
    ...(parts ? parts.variations.map(v => `- **How to confirm (${text(v.label, ctx)}):** ${v.evidence}`) : []),
    ...noteValues(g.issues, 'confirm').map(value => `- **How to confirm:** ${text(value, ctx)}`),
    ...ids.filter(id => validationHint(id)).map(id => `- **${text(id, ctx)}:** ${validationHint(id)}`),
    ...(COMMANDS[title] ? [`- **Validation command:** ${codeSpan(COMMANDS[title])}`] : []));
  lines.push('## Recorded evidence (all instances)',
    ...g.issues.map(i => `${recordedEvidence(i, ctx)}\n  - Description: ${text(i.description, ctx)}`),
    ...(g.evidence.length ? ['### Supporting observations', ...g.evidence.map(i => `${recordedEvidence(i, ctx)}\n  - Description: ${text(i.description, ctx)}`)] : []));
  return joinBlocks(lines);
}

// characters Windows refuses in a file name, and control characters
const UNSAFE_NAME = /[<>:"/\\|?*\x00-\x1f]/g; // eslint-disable-line no-control-regex

/** A finding's file name: its title, without the characters Windows refuses in a name. */
export function findingFileName(title) {
  const name = String(title).replace(UNSAFE_NAME, '-').replace(/[. ]+$/, '').trim();
  return `${name || 'Finding'}.md`;
}
/** The file name of a finding's tester notes. */
export const testerNotesFileName = title => findingFileName(`${title} - tester notes`);
// the first line of every tester notes file: marks it as the tool's own
const TESTER_NOTES_MARKER = '<!-- Electronegativity tester notes: not part of the client report -->';

const COVERAGE_TITLE = 'Validation Coverage and Test Outcomes';
function coverageDocument(issues, ctx) {
  const records = issues.filter(i => /COVERAGE/.test(i.id) || /^RUNTIME_CAMPAIGN_(CASE|RESTORE|CLEANUP)$/.test(i.id) || /^RUNTIME_DOCX_/.test(i.id));
  if (!records.length) return undefined;
  return `${TESTER_NOTES_MARKER}\n\n# ${COVERAGE_TITLE}\n\nThese are test outcomes and coverage limitations, not additional vulnerability findings. Acceptance, opening a view and absence of a signal do not prove execution or safety. Restore and cleanup warnings describe the test state.\n\n${records.map(i => `- ${text(i.description, ctx)}\n\n${recordedEvidence(i, ctx)}`).join('\n\n')}\n`;
}

/**
 * One Markdown document per finding: [{ title, file, content }]. meta.dir is the folder the files go in (links to
 * screenshots are relative to it); meta.root the scanned folder.
 */
export function renderClientFindings(issues, meta = {}) {
  const all = [...issues, ...(meta.suppressed || [])];
  return groupClientFindings(all).map(g => {
    const file = findingFileName(g.definition[0]);
    const ctx = context({ ...meta, outputFile: meta.dir ? path.join(meta.dir, file) : meta.outputFile });
    return { title: g.definition[0], file, content: `${renderGroup(g, ctx)}\n` };
  });
}

/**
 * The tester's notes: one document per finding, and one of the validation coverage when test outcomes exist:
 * [{ title, file, content }]. meta.dir is the folder they go in.
 */
export function renderTesterNotes(issues, meta = {}) {
  const all = [...issues, ...(meta.suppressed || [])];
  const notes = groupClientFindings(all).map(g => {
    const file = testerNotesFileName(g.definition[0]);
    const ctx = context({ ...meta, outputFile: meta.dir ? path.join(meta.dir, file) : meta.outputFile });
    return { title: g.definition[0], file, content: `${testerNotesDocument(g, ctx, findingFileName(g.definition[0]))}\n` };
  });
  const file = findingFileName(COVERAGE_TITLE);
  const coverage = coverageDocument(all, context({ ...meta, outputFile: meta.dir ? path.join(meta.dir, file) : meta.outputFile }));
  if (coverage) notes.push({ title: COVERAGE_TITLE, file, content: coverage });
  return notes;
}

// the client deliverables of a run: the findings and the components workbook they refer to
export const MARKDOWN_FOLDER = 'reports';
// the tester's working notes for each finding, next to the client findings
export const TESTER_NOTES_FOLDER = 'testerNotes';

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
// a tester notes file this report wrote
const isNotesFile = (file) => {
  try {
    return fs.readFileSync(file, 'utf8').startsWith(TESTER_NOTES_MARKER);
  } catch {
    return false;
  }
};
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
 * Writes the client findings into <folder>/reports, one file per finding named after its title, and the tester's notes
 * into <folder>/testerNotes, replacing the files an earlier run left there. Returns the finding files written.
 */
export function writeClientMarkdown(folder, issues, meta = {}, subfolder = MARKDOWN_FOLDER, notesSubfolder = TESTER_NOTES_FOLDER) {
  const dir = path.join(folder, subfolder);
  const notesDir = path.join(folder, notesSubfolder);
  const findings = renderClientFindings(issues, { ...meta, dir, reportRoot: folder });
  const notes = renderTesterNotes(issues, { ...meta, dir: notesDir, reportRoot: folder });
  // nothing is written until every file is known to be the tool's own
  for (const [where, documents, owned] of [[dir, findings, isFindingFile], [notesDir, notes, isNotesFile]])
    for (const document of documents) {
      const file = path.join(where, document.file);
      if (fs.existsSync(file) && !owned(file)) throw new Error(`Refusing to overwrite a Markdown file not owned by this report: ${file}`);
    }
  const write = (where, documents, owned) => {
    fs.mkdirSync(where, { recursive: true });
    const previous = fs.readdirSync(where).filter(name => /\.md$/i.test(name) && owned(path.join(where, name)));
    const files = documents.map(document => {
      const file = path.join(where, document.file);
      fs.writeFileSync(file, document.content);
      return file;
    });
    const current = new Set(documents.map(d => d.file));
    for (const name of previous) if (!current.has(name)) fs.rmSync(path.join(where, name));
    return files;
  };
  const files = write(dir, findings, isFindingFile);
  write(notesDir, notes, isNotesFile);
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
  return groups.length ? `${groups.map(g => renderGroup(g, ctx)).join('\n\n')}\n` : `No reportable findings were identified in ${text(ctx.app, ctx)}.\n`;
}
