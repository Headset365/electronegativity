// Client-facing findings, grouped by the security problem rather than by scanner check.
import path from 'node:path';
import YAML from 'yaml';
import { consequenceOf, interactionOf, worstCase, validationHint } from '../finder/consequences.js';
import { remediationOf } from '../finder/remediation.js';

const definitions = [
  ['Renderer Isolation Weakened', /^(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX|REMOTE_MODULE|AFFINITY|HTTP_RESOURCES_WITH_NODE_INTEGRATION|RUNTIME_(NODE_INTEGRATION|CONTEXT_ISOLATION|SANDBOX))/, 'Untrusted content may gain access to privileged application capabilities.', 'Isolate renderers, disable Node integration and keep the sandbox enabled.', 'CWE-653: Improper Isolation or Compartmentalization'],
  ['Chromium Security Features Disabled', /^(WEB_SECURITY|INSECURE_CONTENT|EXPERIMENTAL_FEATURES|BLINK_FEATURES|WEBGL|WEBSQL|PLUGINS|NAVIGATE_ON_DRAG_DROP|CUSTOM_ARGUMENTS|SECURITY_WARNINGS_DISABLED|SECUREKEYBOARDENTRY|RUNTIME_WEB_SECURITY)/, 'Disabled browser safeguards expand what page content can do.', 'Restore Chromium defaults and enable only capabilities that are essential.', 'CWE-693: Protection Mechanism Failure'],
  ['Privileged APIs Exposed to Untrusted Content', /^(CONTEXT_BRIDGE_EXPOSURE|RUNTIME_PRELOAD_FOREIGN_ORIGIN|WINDOW_SESSION|RUNTIME_WINDOW_SESSION)/, 'Untrusted pages may reach privileged APIs or share a trusted session.', 'Expose narrow preload APIs and separate sessions by trust level.', 'CWE-749: Exposed Dangerous Method or Function'],
  ['IPC Handlers Trust Renderer Input', /^(IPC_SENDER_VALIDATION|IPC_HANDLER|IPC_FILE_ACCESS|IPC_CHANNEL_MAP|RUNTIME_MARKER_IPC)/, 'Renderer messages can reach main-process operations without adequate checks.', 'Validate the sender, arguments and allowed operations in every handler.', 'CWE-20: Improper Input Validation'],
  ['Unsafe Hand-off of URLs and Files to the Operating System', /^(OPEN_EXTERNAL|OPEN_PATH|SHOWITEMINFOLDER|WRITE_SHORTCUT|DOWNLOAD|RUNTIME_(OPEN_EXTERNAL|OPEN_PATH)|RUNTIME_MARKER_(OPEN_EXTERNAL|OPEN_PATH))/, 'Untrusted URLs or file paths may be opened by the operating system.', 'Allowlist URL schemes and hosts, and constrain file paths before opening them.', 'CWE-73: External Control of File Name or Path'],
  ['Code or Command Execution from Untrusted Data', /^(COMMAND_INJECTION|DANGEROUS_FUNCTIONS|RUNTIME_MARKER_COMMAND)/, 'Untrusted data may reach command or code execution.', 'Avoid command-line construction and pass validated arguments to safe APIs.', 'CWE-78: Improper Neutralization of Special Elements used in an OS Command'],
  ['Microsoft Word Integration', /^WORD_LAUNCH/, 'Opening documents in Microsoft Word can expose users to unsafe document content or command construction.', 'Validate document paths and preserve Mark-of-the-Web metadata before opening files.', 'CWE-73: External Control of File Name or Path'],
  ['Deep Link, Protocol and File Association Handling', /^(FILE_HANDLER|PROTOCOL_HANDLER|PROTOCOL_PRIVILEGES|INSTALLER_FILE_HANDLER|UNTRUSTED_LOAD_URL|FILE_PROTOCOL)/, 'External links and files can enter privileged application flows.', 'Parse deep links and file associations as untrusted input and allow only known actions.', 'CWE-20: Improper Input Validation'],
  ['Insufficient Navigation and Window Controls', /^(LIMIT_NAVIGATION|WINDOW_OPEN_HANDLER|NAVIGATION_REDIRECT|AUXCLICK|ALLOWPOPUPS|WEBVIEW|IFRAME_SANDBOX|RUNTIME_(NAVIGATION|NEW_WINDOW|REDIRECT|WEBVIEW)|RUNTIME_MARKER_(NAVIGATION|NEW_WINDOW))/, 'Untrusted navigation or new windows may retain application privileges.', 'Deny navigation and new windows by default, then allowlist intended destinations.', 'CWE-601: URL Redirection to Untrusted Site'],
  ['Missing Permission Handlers', /^(PERMISSION_REQUEST_HANDLER|RUNTIME_PERMISSION|RUNTIME_PERMISSION_CHECK)/, 'Pages may obtain capabilities without an explicit application decision.', 'Install request and check handlers that deny permissions by default.', 'CWE-862: Missing Authorization'],
  ['Cross-Site Scripting Exposure in Content Rendering', /^(XSS_SINK|RICH_TEXT_EDITOR|SANITIZER_CONFIG|ANGULAR|RUNTIME_DOM_INJECTION|RUNTIME_MARKER|RUNTIME_HTML_ENDPOINT|RUNTIME_(ACTIVE_SCRIPT|CAMPAIGN_SCRIPT)|TRAFFIC_WS_HTML_MESSAGE|TRAFFIC_REFLECTED_INPUT)/, 'Untrusted content may be rendered as executable markup.', 'Render text as text; sanitise allowed HTML before insertion into the page.', 'CWE-79: Improper Neutralization of Input During Web Page Generation'],
  ['Missing or Weak Content Security Policy', /^(CSP$|CSP_DIRECTIVES|RUNTIME_CSP)/, 'A missing or permissive policy reduces protection against script injection.', 'Ship a restrictive Content Security Policy for every renderer.', 'CWE-693: Protection Mechanism Failure'],
  ['Document Parsing Risks', /^DOCUMENT_PIPELINE/, 'Documents enter parsers or renderers that need strict isolation.', 'Validate file types and parse untrusted documents in a restricted context.', 'CWE-20: Improper Input Validation'],
  ['Insecure Electron Fuse Configuration', /^(FUSES|PACKAGED_FUSES)/, 'Packaged Electron fuses leave unnecessary privileges available.', 'Set secure fuses at package time and verify the packaged executable.', 'CWE-693: Protection Mechanism Failure'],
  ['Application Code Not Protected Against Inspection or Tampering', /^(ASAR_INTEGRITY|SOURCE_MAP_SHIPPED)/, 'Packaged application code may be exposed or changed without detection.', 'Remove production source maps and enable asar integrity with the associated fuses.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Executable Signing and Exploit Mitigations (hardening)', /^(CODE_SIGNING|BINARY_HARDENING)/, 'The executable lacks a signing or binary hardening safeguard.', 'Sign releases and enable platform exploit mitigations.', 'CWE-693: Protection Mechanism Failure'],
  ['Insecure Update Mechanism', /^UPDATE_SECURITY/, 'The update channel may install software without sufficient verification.', 'Use an authenticated update channel and verify publisher signatures.', 'CWE-494: Download of Code Without Integrity Check'],
  ['Development and Debugging Features in Production', /^(DEVTOOLS|DEVELOPMENT_CODE|DEBUG_LOGGING|RUNTIME_SECRET_IN_CONSOLE|RUNTIME_UNCAUGHT_EXCEPTION)/, 'Development features can disclose information or expand the attack surface.', 'Remove debug facilities and sensitive logs from production builds.', 'CWE-489: Active Debug Code'],
  ['Hard-coded Secrets in the Application Package', /^HARDCODED_SECRET/, 'Secrets shipped in the application package can be recovered by anyone with the package.', 'Remove and rotate embedded secrets; keep server credentials on the server.', 'CWE-798: Use of Hard-coded Credentials'],
  ['Sensitive Data Stored Insecurely', /^(STORAGE|SECRET_FILE_WRITE|ELECTRON_STORE_ENCRYPTION|PLAINTEXT_SECRETS)/, 'Sensitive data may be recoverable from local storage.', 'Use the operating system credential store or safeStorage for secrets.', 'CWE-312: Cleartext Storage of Sensitive Information'],
  ['Insecure Transport and Certificate Validation', /^(HTTP_RESOURCES|RUNTIME_INSECURE_LOAD|TRAFFIC_(CLEARTEXT_HTTP|WS_CLEARTEXT|BASIC_AUTH|INSECURE_COOKIE)|COOKIE_FLAGS|CERTIFICATE|NODE_TLS_REJECT_UNAUTHORIZED|RUNTIME_CERTIFICATE_ERROR)/, 'Traffic or credentials may be exposed in transit.', 'Use HTTPS and WSS, validate certificates and set secure cookie attributes.', 'CWE-319: Cleartext Transmission of Sensitive Information'],
  ['Sensitive Data Exposed in Network Traffic', /^(TRAFFIC_(SECRET_IN_URL|SECRET_IN_RESPONSE|WS_SECRET|AUTH_TO_THIRD_PARTY|USER_INPUT_TO_THIRD_PARTY))/, 'Network requests may expose credentials or user data to unintended recipients.', 'Restrict data sent to each host and remove secrets from URLs and responses.', 'CWE-201: Insertion of Sensitive Information Into Sent Data'],
  ['Outdated Electron Runtime', /^(AVAILABLE_SECURITY_FIXES|UNSUPPORTED_VERSION|CHROMIUM_ADVISORIES)/, 'The Electron runtime may lack security fixes or support.', 'Upgrade to a supported Electron release with the relevant fixes.', 'CWE-1104: Use of Unmaintained Third Party Components'],
  ['Outdated Third-Party Components', /^(DEPENDENCY_VULNERABILITIES|END_OF_LIFE_LIBRARY)/, 'Application dependencies may be outdated or affected by published advisories.', 'Upgrade affected dependencies to supported, fixed releases.', 'CWE-1104: Use of Unmaintained Third Party Components'],
  ['Known Malicious Package', /^MALICIOUS_DEPENDENCY/, 'A known malicious package was detected in the dependency inventory.', 'Remove the package immediately and rotate potentially exposed secrets.', 'CWE-506: Embedded Malicious Code'],
];

const other = ['Other Security Observations', null, 'Additional scanner observations require assessment.', 'Investigate the listed observations and apply the linked guidance.', 'CWE-693: Protection Mechanism Failure'];
const evidenceOnly = /^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|PRELOAD|IPC_RENDERER_CHANNEL|RUNTIME_IPC$|RUNTIME_MARKER_SENT|CREDENTIAL_ACCESS|DEPENDENCY_INVENTORY|ELECTRON_VERSION)/;
const observations = new Set(['SOURCE_MAP_SHIPPED', 'STORAGE_CACHED_RESPONSES', 'CERTIFICATE_PINNING', 'WORD_LAUNCH']);
const normalId = id => String(id || '').replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, '');
const location = i => `${i.file || 'Application-wide'}${i.location?.line ? `:${i.location.line}` : ''}`;
const nameOf = i => i?.name || i || '';
const isConfirmed = i => i.validation?.status === 'confirmed' || i.properties?.executed === true ||
  /^RUNTIME_/.test(i.id) && (i.properties?.execution === 'observed' || i.properties?.live === true || i.severity?.name !== 'INFORMATIONAL');
const victimAction = i => /\b(click|open(?:ing)?|install|updat|import|attachment|document)\b/i.test(interactionOf(i.id) || '');
const consequenceScale = ['Very Low', 'Low', 'Medium', 'High', 'Critical'];
const likelihoodScale = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Very Likely'];

function reportable(i) {
  const id = normalId(i.id);
  if (/_(DEPRECATION|REMOVAL|CHANGE)$/.test(id) || id === 'IPC_SEND_STRUCTURED_CLONE_ALGORITHM' ||
      ['TRAFFIC_IDOR_CANDIDATE', 'TRAFFIC_STATE_CHANGE_NO_AUTH'].includes(id) || /COVERAGE/.test(id)) return false;
  if (evidenceOnly.test(id) || /^(CSP_(JS|HTML)|NAVIGATION_REDIRECT_JS)_CHECK$/.test(i.id) || (id === 'RUNTIME_MARKER' && !i.properties?.live) ||
      (['IPC_HANDLER', 'IPC_CHANNEL_MAP', 'DOCUMENT_PIPELINE'].includes(id) && nameOf(i.severity) === 'INFORMATIONAL')) return false;
  return nameOf(i.severity) !== 'INFORMATIONAL' || observations.has(id);
}

function groupOf(i) {
  const id = normalId(i.id);
  if (['RUNTIME_OPEN_PATH', 'RUNTIME_MARKER_OPEN_PATH'].includes(id) && /\.(?:docx?|rtf)\b/i.test(i.description || '')) return definitions[6];
  return definitions.find(g => g[1].test(id)) || other;
}

function evidenceGroupOf(i) {
  const id = normalId(i.id);
  if (id === 'CSP') return 'Missing or Weak Content Security Policy';
  if (id === 'NAVIGATION_REDIRECT') return 'Insufficient Navigation and Window Controls';
  if (/^(RUNTIME_MARKER|RUNTIME_MARKER_SENT)$/.test(id)) return 'Cross-Site Scripting Exposure in Content Rendering';
  if (/^(IPC_HANDLER|IPC_CHANNEL_MAP|IPC_RENDERER_CHANNEL|RUNTIME_IPC)$/.test(id)) return 'IPC Handlers Trust Renderer Input';
  if (/^(WINDOW_SUMMARY|RUNTIME_WINDOW_SUMMARY|EXPOSED_API|PRELOAD)$/.test(id)) return 'Renderer Isolation Weakened';
  if (id === 'DEPENDENCY_INVENTORY') return 'Outdated Third-Party Components';
  if (id === 'ELECTRON_VERSION') return 'Outdated Electron Runtime';
  if (id === 'CREDENTIAL_ACCESS') return 'Sensitive Data Stored Insecurely';
  if (id === 'DOCUMENT_PIPELINE') return 'Document Parsing Risks';
  return undefined;
}

export function ratingOf(i, title) {
  const id = normalId(i.id);
  const severity = nameOf(i.severity);
  if (severity === 'INFORMATIONAL' || observations.has(id) && severity === 'INFORMATIONAL' ||
      title === 'Outdated Third-Party Components' && !(i.properties?.advisories?.length || i.properties?.packages?.some(p => p.advisories?.length)) ||
      title === 'Executable Signing and Exploit Mitigations (hardening)' && severity === 'LOW') return { consequence: 'N/A', likelihood: 'N/A' };
  const route = consequenceOf(i.id)?.route;
  let c = ({ HIGH: 3, MEDIUM: 2, LOW: 1 })[severity] ?? 0;
  if (route === 'local') c = Math.max(0, c - 1);
  if (id === 'MALICIOUS_DEPENDENCY' || ['RUNTIME_ACTIVE_SCRIPT', 'RUNTIME_CAMPAIGN_SCRIPT'].includes(id) && isConfirmed(i)) c = 4;
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
    const group = groups.get(evidenceGroupOf(i));
    if (group) group.evidence.push(i);
  }
  return [...groups.values()].map(g => {
    g.items = g.issues.map(i => ({ issue: i, rating: ratingOf(i, g.definition[0]) })).sort(byRating);
    g.rating = g.items[0].rating;
    return g;
  }).sort((a, b) => byRating(a, b) || a.definition[0].localeCompare(b.definition[0]));
}

function safeInline(value) { return String(value ?? '').replace(/\r?\n/g, ' ').trim(); }
function unique(values) { return [...new Set(values.filter(Boolean))]; }
function strings(value) { return (Array.isArray(value) ? value : value == null ? [] : [value]).filter(v => typeof v === 'string' && v.trim()); }
function noteValues(issues, field) { return unique(issues.flatMap(i => strings(i.notes?.[field]))); }
function language(file) {
  return ({ js: 'javascript', cjs: 'javascript', mjs: 'javascript', jsx: 'jsx', ts: 'typescript', tsx: 'tsx', json: 'json', html: 'html', css: 'css', ps1: 'powershell', sh: 'bash' })[path.extname(file || '').slice(1).toLowerCase()] || 'text';
}
function code(value, lang) {
  const source = String(value).trim();
  const fence = '`'.repeat(Math.max(3, ...[...source.matchAll(/`+/g)].map(m => m[0].length + 1)));
  return `${fence}${lang}\n${source}\n${fence}`;
}
function details(i) {
  const p = i.properties || {};
  return [location(i), p.url, p.window, p.channel && `channel ${p.channel}`, p.fuse && `fuse ${p.fuse}=${p.value}`, p.cookie && `cookie ${p.cookie}`, p.host].filter(Boolean).join(' — ');
}
function proseNotes(g) {
  const i = g.items[0].issue;
  const notes = [`Rating basis — ${i.id} at ${location(i)}, ${nameOf(i.severity)} severity, ${nameOf(i.confidence)} confidence; ${isConfirmed(i) ? 'confirmed during a watch session' : 'not confirmed at runtime'}.`];
  if (g.definition[0] === 'Sensitive Data Exposed in Network Traffic') notes.push('Remove third-party traffic observations if the listed hosts belong to the client.');
  if (g.definition[0] === 'Microsoft Word Integration') notes.push('Remove the Protected View paragraph if opened documents retain Zone.Identifier.');
  if (g.definition[0] === 'IPC Handlers Trust Renderer Input') notes.push('Remove dead-channel observations if served renderer code uses the channel.');
  for (const s of g.issues.filter(x => x.suppression)) notes.push(`Accepted risk — ${s.id} at ${location(s)}. ${s.suppression.reason || 'No reason supplied.'}${s.suppression.owner ? ` Owner ${s.suppression.owner}.` : ''}${s.suppression.expires ? ` Expires ${s.suppression.expires}.` : ''}`);
  return notes;
}

function renderGroup(g, meta) {
  const [title, , about, fix, cwe] = g.definition;
  const app = safeInline(meta.app?.name || 'the application');
  const ids = unique(g.issues.map(i => i.id));
  const affected = unique(g.issues.map(details));
  const top = g.items[0].issue;
  const examples = unique(g.issues.map(i => i.sample).filter(Boolean)).slice(0, 8);
  const notes = field => noteValues(g.issues, field).map(value => `- ${safeInline(value)}`);
  const lines = [`---\n${YAML.stringify({ Title: title, Consequence: g.rating.consequence, Likelihood: g.rating.likelihood, Notes: proseNotes(g) }).trimEnd()}\n---`,
    `# ${title}`, '## Issue Description', `${app}: ${about}`,
    ...ids.map(id => `- **${id}** — ${safeInline(g.issues.find(i => i.id === id).description || (typeof __ === 'function' && __(id)) || id)}`),
    ...notes('about'),
    '## Affected', `The following locations or components in ${app} were affected:`,
    ...affected.slice(0, 60).map(x => `- ${safeInline(x)}`),
    ...(affected.length > 60 ? [`- …and ${affected.length - 60} more.`] : []),
    '## Implication', about,
    ...(consequenceOf(top.id)?.text ? [consequenceOf(top.id).text] : []),
    ...(worstCase(top.id) ? [`The worst credible outcome is ${worstCase(top.id)}`] : []),
    ...(interactionOf(top.id) ? [`Victim interaction: ${interactionOf(top.id)}.`] : []),
    ...notes('impact'), ...notes('reachability'),
    '## Reproduction and Evidence',
    ...noteValues(g.issues, 'preconditions').map(value => `- **Precondition:** ${safeInline(value)}`),
    ...noteValues(g.issues, 'steps').map(value => `- **Reproduction step:** ${safeInline(value)}`),
    ...examples.map(sample => {
      const item = g.issues.find(i => i.sample === sample);
      return `- ${safeInline(location(item))}\n\n${code(sample, language(item.file))}`;
    }),
    ...unique(g.issues.flatMap(i => strings(i.properties?.evidence))).slice(0, 8).map(value => `- Observed evidence: ${safeInline(value)}`),
    ...g.issues.filter(i => i.validation || i.properties?.screenshot).slice(0, 8).map(i => `- ${safeInline(location(i))}: ${safeInline(i.validation?.status || 'Evidence')} — ${safeInline(i.validation?.text || '')}${i.properties?.screenshot ? `; screenshot ${i.properties.screenshot}` : ''}`),
    ...g.evidence.slice(0, 8).map(i => `- Supporting observation at ${safeInline(location(i))}: ${safeInline(i.description)}${i.properties?.screenshot ? `; screenshot ${i.properties.screenshot}` : ''}`),
    ...noteValues(g.issues, 'confirm').map(value => `- **How to confirm:** ${safeInline(value)}`),
    ...unique(ids.map(validationHint)).slice(0, 3).map(x => `- ${safeInline(x)}`),
    '## Recommendations', `- ${fix}`, ...notes('recommendation')];
  if (title === 'Microsoft Word Integration') lines.push('- Preserve Mark-of-the-Web (`Zone.Identifier`) so Word can apply Protected View.', '- Verify the stream on an opened document with `Get-Item <doc> -Stream Zone.Identifier`.');
  if (title === 'Insecure Electron Fuse Configuration') lines.push('- Re-read packaged fuses with `npx @electron/fuses read --app "<exe>"`.');
  if (title === 'Application Code Not Protected Against Inspection or Tampering') lines.push('- Check `EnableEmbeddedAsarIntegrityValidation` and `OnlyLoadAppFromAsar` in the fuse finding.', '- Inspect packaged source with `npx @electron/asar extract app.asar out`.');
  if (title === 'Sensitive Data Stored Insecurely') lines.push('- Check the `EnableCookieEncryption` fuse when credentials are stored in cookies.');
  if (title === 'Outdated Third-Party Components') {
    const sheet = (meta.outputs || []).find(o => /\.xlsx$/i.test(o));
    if (sheet) {
      const relative = meta.outputFile ? path.relative(path.dirname(path.resolve(meta.outputFile)), path.resolve(sheet)) : path.basename(sheet);
      lines.push(`- Review each flagged component, advisory and fixed version in [${path.basename(sheet)}](${encodeURI(relative.split(path.sep).join('/'))}).`);
    }
  }
  for (const id of ids) {
    const remedy = remediationOf(id);
    if (remedy?.fix && remedy.fix !== fix) lines.push(`- **${id}** — ${safeInline(remedy.fix)}`);
    if (remedy?.example) lines.push(code(remedy.example, /<\w|webPreferences/.test(remedy.example) ? 'javascript' : 'javascript'));
  }
  const number = /^CWE-(\d+)/.exec(cwe)?.[1];
  lines.push('## References', `- ${cwe}\n\n  https://cwe.mitre.org/data/definitions/${number}.html`);
  for (const url of unique(g.issues.map(i => i.shortenedURL)).slice(0, 8)) lines.push(`- Check guidance\n\n  ${url}`);
  lines.push('- Electron security guidance\n\n  https://www.electronjs.org/docs/latest/tutorial/security');
  if (title === 'Microsoft Word Integration') lines.push('- Microsoft Protected View\n\n  https://learn.microsoft.com/en-us/office/troubleshoot/word/office-file-opens-in-protected-view');
  return lines.reduce((text, line) => text + (text && text.split('\n').at(-1).startsWith('- ') && line.startsWith('- ') ? '\n' : '\n\n') + line, '').trim();
}

/** Complete unredacted Markdown report. Suppressed findings stay visible as accepted risks. */
export function renderClientMarkdown(issues, meta = {}) {
  return groupClientFindings([...issues, ...(meta.suppressed || [])]).map(g => renderGroup(g, meta)).join('\n\n') + '\n';
}
