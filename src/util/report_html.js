// Self-contained HTML report: no external resources, so it can be archived, attached to tickets or opened offline.
import { ROUTES, ROUTE_IMPACT, consequenceOf, validationHint, worstCase, interactionOf } from '../finder/consequences.js';
import { NOTE_FIELDS } from '../report/notes.js';
import { scores } from '../report/scores.js';

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const CONFIDENCES = ['CERTAIN', 'FIRM', 'TENTATIVE'];

const escapeHtml = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// Only http(s) links are rendered as links, anything else is shown as text
const safeUrl = (url) => /^https?:\/\//i.test(url || '') ? url : undefined;

function advisoryLinks(ids) {
  const links = ids.map(id => `<a href="https://osv.dev/vulnerability/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${escapeHtml(id)}</a>`).join(', ');
  return ids.length > 6 ? `<details><summary>${ids.length} advisories</summary>${links}</details>` : `Advisories: ${links}`;
}

// Code samples from minified bundles can be a single line of many kilobytes: show the start and say how much was cut
const SAMPLE_LIMIT = 3000;
function sampleBlock(sample) {
  const text = String(sample);
  const lines = text.split('\n').length;
  const cut = text.length > SAMPLE_LIMIT ? text.length - SAMPLE_LIMIT : 0;
  const shown = cut ? text.slice(0, SAMPLE_LIMIT) : text;
  const size = lines > 1 ? `${lines} lines` : `${text.length} characters`;
  return `<details class="code"><summary>Code (${size})</summary><pre class="sample"><code>${escapeHtml(shown)}</code></pre>${cut ? `<div class="cut">${cut} more characters not shown; open the file at the location above.</div>` : ''}</details>`;
}

const VALIDATION_LABELS = { confirmed: 'Confirmed at runtime', observed: 'Seen at runtime', safe: 'Ruled out at runtime' };
// accepted risks (--baseline, --suppress) and the comparison with the previous scan (--compare)
function triageSection(meta) {
  const suppressed = meta.suppressed || [];
  const comparison = meta.comparison;
  let out = '';
  if (comparison) out += `
  <h2>Since the previous scan</h2>
  <p class="note">Compared with ${escapeHtml(comparison.file)}: <b>${escapeHtml(comparison.new)}</b> new, <b>${escapeHtml(comparison.unchanged)}</b> unchanged, <b>${escapeHtml(comparison.changed.length)}</b> with a different severity, <b>${escapeHtml(comparison.fixed.length)}</b> fixed.</p>${comparison.changed.length ? `
  <ul>${comparison.changed.map(c => `<li><code>${escapeHtml(c.id)}</code> in ${escapeHtml(c.file)}: ${escapeHtml(c.from)} → ${escapeHtml(c.to)}</li>`).join('')}</ul>` : ''}${comparison.fixed.length ? `
  <details><summary>Fixed since (${escapeHtml(comparison.fixed.length)})</summary><ul>${comparison.fixed.map(f => `<li><span class="badge sev-${escapeHtml(String(f.severity).toLowerCase())}">${escapeHtml(f.severity)}</span> <code>${escapeHtml(f.id)}</code> ${escapeHtml(f.file)}${f.line ? `:${escapeHtml(f.line)}` : ''} ${escapeHtml(f.description)}</li>`).join('')}</ul></details>` : ''}`;
  if (suppressed.length) out += `
  <h2>Accepted risks (${suppressed.length})</h2>
  <p class="note">Findings accepted in the baseline or the suppressions file: they are not counted in the scores or by --fail-on.</p>
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Finding</th><th>Location</th><th>Reason</th><th>Owner</th><th>Until</th></tr></thead>
    <tbody>${suppressed.map(i => `
      <tr><td><span class="badge sev-${escapeHtml(i.severity.name.toLowerCase())}">${escapeHtml(i.severity.name)}</span> <code>${escapeHtml(i.id)}</code><div class="muted">${escapeHtml(String(i.description).slice(0, 200))}</div></td><td class="loc">${escapeHtml(place(i))}</td>
        <td>${escapeHtml((i.suppression && i.suppression.reason) || i.baselineReason || '')}</td><td>${escapeHtml((i.suppression && i.suppression.owner) || '')}</td><td>${escapeHtml((i.suppression && i.suppression.expires) || '')}</td></tr>`).join('')}
    </tbody>
  </table></div>`;
  return out;
}

// your own notes on the finding (--finding-notes)
function notesBlock(notes) {
  if (!notes) return '';
  const fields = NOTE_FIELDS.filter(([key]) => notes[key]).map(([key, label]) => {
    const value = notes[key];
    return `<div><b>${escapeHtml(label)}:</b> ${Array.isArray(value) ? `<ul>${value.map(v => `<li>${escapeHtml(v)}</li>`).join('')}</ul>` : escapeHtml(value)}</div>`;
  });
  return fields.length ? `<details class="howto" open><summary>Notes</summary>${fields.join('')}</details>` : '';
}

function validationBlock(issue) {
  if (issue.validation) return `<div class="validation v-${escapeHtml(issue.validation.status)}"><b>${escapeHtml(VALIDATION_LABELS[issue.validation.status] || 'Validation')}</b> ${escapeHtml(issue.validation.text.replace(/^(Confirmed|Seen|Checked) at runtime: /, ''))}</div>`;
  const hint = issue.manualReview ? validationHint(issue.id) : undefined;
  return hint ? `<details class="howto"><summary>How to validate</summary><div>${escapeHtml(hint)}</div></details>` : '';
}
const validationState = (issue) => issue.validation ? issue.validation.status : issue.manualReview ? 'open' : 'none';

function findingRow(issue, index) {
  const sev = issue.severity.name;
  const conf = issue.confidence.name;
  const position = issue.file !== 'N/A' && issue.location && issue.location.line ? `:${issue.location.line}:${issue.location.column}` : '';
  const location = issue.file === 'N/A' ? 'Application-wide' : issue.file;
  const url = safeUrl(issue.shortenedURL);
  const advisories = issue.properties && Array.isArray(issue.properties.advisories) ? issue.properties.advisories : undefined;
  const consequence = consequenceOf(issue.id);
  const route = consequence ? consequence.route : 'other';
  const searchText = [issue.id, issue.file, issue.description, String(issue.sample ?? '').slice(0, SAMPLE_LIMIT), consequence && consequence.text].join(' ').toLowerCase();

  return `
      <tr class="finding" data-severity="${sev}" data-confidence="${conf}" data-check="${escapeHtml(issue.id)}" data-manual="${issue.manualReview ? 1 : 0}" data-route="${route}" data-validation="${escapeHtml(validationState(issue))}" data-new="${issue.comparison === 'new' || issue.comparison === 'changed' ? 1 : 0}" data-text="${escapeHtml(searchText)}" data-index="${index}">
        <td><span class="badge sev-${sev.toLowerCase()}">${sev === 'INFORMATIONAL' ? 'INFO' : sev}</span></td>
        <td>
          <div class="check">${escapeHtml(issue.id)}${issue.manualReview ? ' <span class="review" title="Requires manual review">review</span>' : ''}${issue.comparison === 'new' ? ' <span class="review" title="Not in the previous report">new</span>' : issue.comparison === 'changed' ? ' <span class="review" title="Its severity changed since the previous report">severity changed</span>' : ''}</div>
          <div class="desc">${escapeHtml(issue.description)}</div>
          ${consequence ? `<div class="consequence"><span class="route route-${route}" title="Who can exploit it">${escapeHtml(consequence.label)}</span> ${escapeHtml(consequence.text)}${interactionOf(issue.id) && route !== 'info' ? ` <span class="interaction">Victim interaction: ${escapeHtml(interactionOf(issue.id))}.</span>` : ''}</div>` : ''}
          ${issue.properties && issue.properties.screenshot ? `<div class="evidence">Screenshot: ${escapeHtml(issue.properties.screenshot)}</div>` : ''}
          ${validationBlock(issue)}
          ${notesBlock(issue.notes)}
          ${issue.sample ? sampleBlock(issue.sample) : ''}
          ${advisories ? `<div class="advisories">${advisoryLinks(advisories)}</div>` : ''}
          ${url ? `<a class="ref" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Reference</a>` : ''}
        </td>
        <td class="loc">${issue.session ? `<div class="session">${escapeHtml(issue.session)}</div>` : ''}${escapeHtml(location)}<span class="pos">${escapeHtml(position)}</span></td>
        <td><span class="conf">${conf}</span></td>
      </tr>`;
}

// Findings grouped by check: what the finding is, what it implies, its impact, and where it was found
const SEVERITY_IMPACT = {
  HIGH: 'Rated high: serious harm if the conditions above hold.',
  MEDIUM: 'Rated medium: harmful in combination with other weaknesses, or under specific conditions.',
  LOW: 'Rated low: limited harm, or hard to reach.',
  INFORMATIONAL: 'Informational.',
};
const localDescription = (id) => {
  try {
    const text = typeof __ === 'function' ? __(id) : undefined;
    return text && text !== id ? text : undefined;
  } catch {
    return undefined;
  }
};

// Chromium, Node.js, V8 and OpenSSL bundled with the Electron release
function bundledText(bundled) {
  if (!bundled) return '';
  const parts = [['Chromium', bundled.chromium], ['Node.js', bundled.node], ['V8', bundled.v8], ['OpenSSL', bundled.openssl]].filter(([, v]) => v);
  return parts.length ? ` (${parts.map(([k, v]) => `${k} ${escapeHtml(v)}`).join(', ')})` : '';
}

function findingGroups(sorted) {
  const groups = new Map();
  for (const issue of sorted) {
    const group = groups.get(issue.id) || { id: issue.id, issues: [], severity: issue.severity };
    group.issues.push(issue);
    if (issue.severity.value > group.severity.value) group.severity = issue.severity;
    groups.set(issue.id, group);
  }
  const routeOrder = ['content', 'escalation', 'network', 'dependency', 'local', 'info', 'other'];
  return [...groups.values()].sort((a, b) => b.severity.value - a.severity.value ||
    routeOrder.indexOf((consequenceOf(a.id) || { route: 'other' }).route) - routeOrder.indexOf((consequenceOf(b.id) || { route: 'other' }).route) ||
    b.issues.length - a.issues.length || a.id.localeCompare(b.id));
}

function groupCard(group) {
  const consequence = consequenceOf(group.id);
  const route = consequence ? consequence.route : 'other';
  const issues = group.issues;
  // what the check detects: its own description, or the shortest description of its findings (the least specific)
  const meaning = localDescription(group.id) || issues.map(i => String(i.description || '')).sort((a, b) => a.length - b.length)[0];
  const statuses = { confirmed: 0, observed: 0, safe: 0, open: 0 };
  for (const issue of issues) {
    const state = validationState(issue);
    if (state in statuses) statuses[state]++;
  }
  const evidence = [
    statuses.confirmed ? `<span class="v-confirmed-t">${statuses.confirmed} confirmed at runtime</span>` : '',
    statuses.observed ? `<span class="v-observed-t">${statuses.observed} seen at runtime</span>` : '',
    statuses.safe ? `<span class="v-safe-t">${statuses.safe} ruled out</span>` : '',
    statuses.open ? `<span>${statuses.open} to review</span>` : '',
  ].filter(Boolean).join(' · ');
  const impact = [
    consequence ? ROUTE_IMPACT[route] : undefined,
    worstCase(group.id) ? `Worst case: ${worstCase(group.id)}` : undefined,
    SEVERITY_IMPACT[group.severity.name],
    statuses.confirmed ? `Runtime evidence proves it in ${statuses.confirmed} place${statuses.confirmed === 1 ? '' : 's'}.` : statuses.safe && !statuses.open && !statuses.observed ? 'The runtime checks ruled it out where they were run.' : undefined,
  ].filter(Boolean);
  const where = issues.slice(0, 12).map(i => `<li>${escapeHtml(i.session ? `[${i.session}] ` : '')}${escapeHtml(i.file === 'N/A' ? 'Application-wide' : place(i))}${i.validation ? ` <span class="v-${escapeHtml(i.validation.status)}-t">(${escapeHtml(VALIDATION_LABELS[i.validation.status] || i.validation.status)})</span>` : ''}</li>`).join('');
  const hint = validationHint(group.id);
  return `
    <details class="group" data-route="${route}">
      <summary><span class="badge sev-${group.severity.name.toLowerCase()}">${group.severity.name === 'INFORMATIONAL' ? 'INFO' : group.severity.name}</span>
        <span class="gid">${escapeHtml(group.id)}</span> <span class="gcount">×${issues.length}</span>
        ${consequence ? `<span class="route route-${route}">${escapeHtml(consequence.label)}</span>` : ''}
        ${evidence ? `<span class="gevidence">${evidence}</span>` : ''}</summary>
      <dl>
        <dt>What it is</dt><dd>${escapeHtml(meaning)}</dd>
        ${consequence ? `<dt>Implication</dt><dd>${escapeHtml(consequence.text)}</dd>` : ''}
        <dt>Impact</dt><dd>${impact.map(escapeHtml).join('<br>')}</dd>
        ${hint ? `<dt>How to validate</dt><dd>${escapeHtml(hint)}</dd>` : ''}
        <dt>Where</dt><dd><ul class="where">${where}${issues.length > 12 ? `<li>and ${issues.length - 12} more</li>` : ''}</ul>
          <button type="button" class="linkish filter-check" data-check="${escapeHtml(group.id)}">Show these ${issues.length} finding${issues.length === 1 ? '' : 's'} below</button></dd>
      </dl>
    </details>`;
}

// The dependency table: one row per package or library version found
const SUPPORT_LABELS = { supported: 'Supported', unsupported: 'Unsupported', outdated: 'Older major', current: 'Latest major', unknown: 'Unknown' };
const npmUrl = (name, version) => `https://www.npmjs.com/package/${name.split('/').map(encodeURIComponent).join('/')}${version ? `/v/${encodeURIComponent(version)}` : ''}`;

const REFERENCE_LABELS = { ADVISORY: 'advisory', FIX: 'fix', REPORT: 'report', ARTICLE: 'article', WEB: 'reference' };
const link = (url, text) => safeUrl(url) ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>` : escapeHtml(text);

// links for the latest version: its npm page, release notes, repository and homepage
function projectLinks(row) {
  const links = [];
  if (row.latest && row.known !== undefined) links.push(link(npmUrl(row.name, row.latest), 'npm'));
  if (row.releaseNotes) links.push(link(row.releaseNotes, 'release notes'));
  if (row.repository && row.repository !== row.releaseNotes) links.push(link(row.repository, 'repository'));
  if (row.homepage && row.homepage !== row.repository && !String(row.homepage).startsWith(`${row.repository}#`)) links.push(link(row.homepage, 'homepage'));
  if (row.support && row.support.policy && safeUrl(row.support.policy)) links.push(link(row.support.policy, 'support policy'));
  return links.length ? `<div class="refs">${links.join(' · ')}</div>` : '';
}

function advisoryList(row) {
  if (row.advisoryError) return '<span class="muted">lookup failed</span>';
  if (row.advisories.length === 0) return '<span class="muted">none known</span>';
  const counts = {};
  for (const a of row.advisories) counts[a.severity || 'UNRATED'] = (counts[a.severity || 'UNRATED'] || 0) + 1;
  const kev = row.advisories.filter(a => a.kev).length;
  const summary = Object.entries(counts).map(([level, n]) => `<span class="adv adv-${level.toLowerCase()}">${n} ${level.toLowerCase()}</span>`).join(' ') +
    (kev ? ` <span class="adv adv-critical">${kev} exploited (KEV)</span>` : '') + (row.malicious ? ' <span class="adv adv-critical">malicious</span>' : '');
  const items = row.advisories.map(a => {
    const cves = a.cves.map(cve => link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`, cve)).join(', ');
    const sources = [link(`https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`, a.cves.length ? a.id : `${a.id} (OSV)`)];
    if (/^GHSA-/.test(a.id)) sources.push(link(`https://github.com/advisories/${encodeURIComponent(a.id)}`, 'GitHub advisory'));
    for (const ref of a.references || []) if (safeUrl(ref.url) && !sources.some(s => s.includes(escapeHtml(ref.url)))) sources.push(link(ref.url, REFERENCE_LABELS[ref.type] || 'reference'));
    const fixed = a.fixed ? ` <span class="muted">(fixed in ${link(npmUrl(row.name, a.fixed), a.fixed)})</span>` : ' <span class="muted">(no fixed version)</span>';
    const exploited = a.kev ? ` <span class="adv adv-critical" title="CISA Known Exploited Vulnerabilities, added ${escapeHtml(a.kev.added || '?')}">exploited in the wild (KEV)${a.kev.ransomware ? ', ransomware' : ''}</span>` : '';
    const epss = a.epss ? ` <span class="muted" title="FIRST EPSS: probability of exploitation in the next 30 days">EPSS ${escapeHtml((a.epss.epss * 100).toFixed(1))}%</span>` : '';
    return `<li>${cves ? `${cves} ` : ''}${a.severity ? `<span class="adv adv-${a.severity.toLowerCase()}">${a.severity.toLowerCase()}</span> ` : ''}${escapeHtml(a.summary)}${exploited}${epss}${fixed}<div class="refs">${sources.join(' · ')}</div></li>`;
  }).join('');
  const fix = row.fixedIn ? `<div class="muted">All fixed in ${escapeHtml(row.fixedIn)}</div>` : row.fixedIn === null ? '<div class="muted">Not all have a fix</div>' : '';
  return `<details><summary>${summary}</summary><ul class="advlist">${items}</ul></details>${fix}`;
}

// Chromium CVEs fixed upstream after the Chromium build in this Electron, minus Electron's backports
function chromiumSection(chromium) {
  if (!chromium) return '';
  if (!chromium.checked) return `
  <h3>Chromium advisories</h3>
  <p class="note">Chromium ${escapeHtml(chromium.chromium || '?')}: ${escapeHtml(chromium.note || 'not checked')}.</p>`;
  const rows = chromium.top.map(r => `
      <tr><td>${link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(r.id)}`, r.id)}${r.kev ? ' <span class="adv adv-critical">KEV</span>' : ''}</td><td><span class="adv adv-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span>${r.score ? ` ${escapeHtml(r.score)}` : ''}</td><td>${escapeHtml(r.fixedIn || '?')}</td><td>${escapeHtml(r.electronFix || '?')}</td><td>${escapeHtml(r.summary || '')}</td></tr>`).join('');
  return `
  <h3 id="chromium">Chromium advisories (Chromium ${escapeHtml(chromium.chromium)})</h3>
  <p class="note"><b>${escapeHtml(chromium.total)}</b> Chromium CVEs were fixed upstream after this build (${Object.entries(chromium.counts).filter(([, n]) => n).map(([level, n]) => `${escapeHtml(n)} ${escapeHtml(level)}`).join(', ')}), <b>${escapeHtml(chromium.kev)}</b> of them exploited in the wild (CISA KEV)${chromium.backportsChecked ? `; ${escapeHtml(chromium.backported)} more were backported into this Electron version and are not counted` : '; Electron\'s backports were not checked, so this is an upper bound'}. NVD lists Chrome CVEs as affecting every earlier version; backports missing from Electron's release notes are not subtracted.${chromium.partial ? ' <b>NVD returned part of the list.</b>' : ''}</p>
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>CVE</th><th>Severity</th><th>Fixed in Chromium</th><th>First Electron with the fix</th><th>Summary</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table></div>`;
}

function behind(row) {
  if (row.versionsBehind === undefined) return '<span class="muted">?</span>';
  if (row.versionsBehind === 0) return 'Up to date';
  return `${row.versionsBehind} release${row.versionsBehind === 1 ? '' : 's'}${row.majorsBehind ? `<div class="muted">${row.majorsBehind} major${row.majorsBehind === 1 ? '' : 's'}</div>` : ''}`;
}

function dependencySection(deps) {
  if (!deps || !deps.rows || deps.rows.length === 0) return '';
  const rows = deps.rows;
  const vulnerable = rows.filter(r => r.advisories.length > 0).length;
  const unsupported = rows.filter(r => r.support.status === 'unsupported').length;
  const outdated = rows.filter(r => r.versionsBehind > 0).length;
  const body = rows.map(r => {
    const issue = r.advisories.length > 0 || r.support.status === 'unsupported' || r.support.status === 'outdated';
    const where = [r.kinds.join(', '), r.direct ? 'direct' : '', r.dev ? 'dev' : ''].filter(Boolean).join(' · ');
    const files = r.files.length ? `<div class="muted files">${r.files.map(escapeHtml).join('<br>')}</div>` : '';
    return `
      <tr class="dep" data-issue="${issue ? 1 : 0}" data-text="${escapeHtml([r.name, r.version, r.kinds.join(' '), r.files.join(' ')].join(' ').toLowerCase())}">
        <td><a class="pkg" href="${npmUrl(r.name)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.name)}</a>${r.malicious ? ` <span class="adv adv-critical">malicious version (${escapeHtml(r.malicious.id)})</span>` : ''}<div class="muted">${escapeHtml(where)}</div>${files}</td>
        <td class="mono">${r.known ? link(npmUrl(r.name, r.version), r.version) : escapeHtml(r.version)}${r.known === false ? '<div class="muted">not on npm</div>' : ''}</td>
        <td class="nowrap">${escapeHtml(r.released || '?')}</td>
        <td class="mono">${r.latest ? link(npmUrl(r.name, r.latest), r.latest) : '?'}${r.latestInMajor && r.latestInMajor !== r.version && r.latestInMajor !== r.latest ? `<div class="muted">${link(npmUrl(r.name, r.latestInMajor), r.latestInMajor)} in this major</div>` : ''}${projectLinks(r)}</td>
        <td class="nowrap">${escapeHtml(r.latestReleased || '?')}</td>
        <td>${behind(r)}</td>
        <td><span class="support support-${r.support.status}">${SUPPORT_LABELS[r.support.status]}</span><div class="muted">${escapeHtml(r.support.detail)}</div></td>
        <td>${r.support.supported && r.support.supported.length ? escapeHtml(r.support.supported.join(', ')) : '<span class="muted">?</span>'}</td>
        <td>${advisoryList(r)}</td>
      </tr>`;
  }).join('');
  return `
  <h2 id="dependencies">Dependencies (${rows.length})</h2>
  <p class="note">Every package and library found: npm packages (lockfile or node_modules), library copies and bundles recognized by their banners, and the Electron runtime. Release dates and versions come from the npm registry, support windows from <a href="https://endoflife.date" target="_blank" rel="noopener noreferrer">endoflife.date</a> where the project publishes one, and advisories from <a href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV</a>.${deps.offline ? ' <b>Scanned with --offline: nothing was looked up.</b>' : ''}${deps.errors && deps.errors.length ? ` ${deps.errors.length} lookup${deps.errors.length === 1 ? '' : 's'} failed.` : ''}</p>
  <div class="depsummary"><span><b>${vulnerable}</b> with known vulnerabilities</span>${deps.intel && deps.intel.checked ? `<span><b>${deps.intel.kev}</b> with vulnerabilities exploited in the wild (CISA KEV)</span>` : ''}${deps.intel && deps.intel.malicious ? `<span class="risk"><b>${deps.intel.malicious}</b> malicious</span>` : ''}<span><b>${unsupported}</b> unsupported</span><span><b>${outdated}</b> not on the latest version</span></div>
  <div class="toolbar">
    <input type="search" id="depsearch" placeholder="Filter by package, version or file" aria-label="Filter dependencies">
    <label><input type="checkbox" id="depissues"> Only vulnerable, unsupported or older major</label>
    <span class="count" id="depcount"></span>
  </div>
  <div class="table-wrap">
    <table class="deps">
      <thead><tr><th>Package</th><th>Version found</th><th>Released</th><th>Latest</th><th>Latest released</th><th>Behind</th><th>Support</th><th>Supported versions</th><th>Known vulnerabilities</th></tr></thead>
      <tbody>${body}
      </tbody>
    </table>
  </div>${chromiumSection(deps.chromium)}`;
}

/**
 * @param {Array} issues findings, as returned by run()
 * @param {Object} meta { version, input, electronVersion, filesScanned, globalChecks, atomicChecks, errors, generatedAt }
 */
const INVENTORY = ['WINDOW_SUMMARY_JS_CHECK', 'EXPOSED_API_JS_CHECK', 'GLOBAL_EXPOSURE_JS_CHECK', 'RUNTIME_WINDOW_SUMMARY', 'RUNTIME_IPC', 'RUNTIME_COVERAGE', 'RUNTIME_WINDOW_COVERAGE', 'CREDENTIAL_ACCESS_JS_CHECK'];

// Where the code reads and writes credentials, unprotected first, and what the data-at-rest review and the --canary
// trace found on disk
function savedCredentials(rows, atRest) {
  const trace = atRest && atRest.credentialTrace;
  if (rows.length === 0 && !trace) return '';
  const order = { read: 0, write: 1, delete: 2 };
  const sorted = [...rows].sort((a, b) => Number(a.properties.protected !== false) - Number(b.properties.protected !== false) ||
    (order[a.properties.op] ?? 3) - (order[b.properties.op] ?? 3) || String(a.file).localeCompare(String(b.file)) || a.location.line - b.location.line).slice(0, 500);
  const protection = (value) => value === true ? 'OS-protected' : value === false ? '<span class="risk">not protected</span>' : '<span class="unknown">check</span>';
  return `
  <h2>Saved credentials</h2>
  <p class="note">Every place the app's code reads, writes or deletes a credential-like value (matched by key and path names: password, remember, credential, token, auth, ...), and whether the operating system protects it. The read rows show where a remembered password is loaded from.</p>${sorted.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Operation</th><th>API</th><th>Key</th><th>Store</th><th>Protection</th><th>At</th></tr></thead>
    <tbody>${sorted.map(r => { const p = r.properties; return `
      <tr><td>${escapeHtml(p.op)}</td><td><code>${escapeHtml(p.api)}</code></td><td>${escapeHtml(p.key || '')}</td><td>${escapeHtml(p.store)}</td><td>${protection(p.protected)}</td><td class="loc">${escapeHtml(place(r))}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${trace ? `
  <p class="note"><b>Test password trace (--canary):</b> ${trace.locations.length > 0 ? `<span class="risk">found in ${escapeHtml(trace.locations.length)} location(s)</span>: ${trace.locations.map(l => `<code>${escapeHtml(l)}</code>`).join(' ')}` : 'not found in plaintext or a common encoding'}; ${escapeHtml(trace.files)} files and ${escapeHtml(trace.leveldbStores)} LevelDB stores searched${trace.credentialManagerNew.length ? `; new Credential Manager entries: ${trace.credentialManagerNew.map(t => escapeHtml(t)).join(', ')}` : ''}.</p>` : ''}`;
}
const place = (issue) => `${issue.file}${issue.location && issue.location.line ? ':' + issue.location.line : ''}`;

// What page script could reach in each window, if content it renders were ever to run as code
function reach(settings) {
  if (!settings) return '';
  const node = settings.nodeIntegration.value === true && settings.sandbox.value !== true;
  if (node) return '<span class="risk">Node.js</span>';
  if (settings.contextIsolation.value === false) return '<span class="risk">preload globals</span>';
  if ([settings.nodeIntegration.value, settings.contextIsolation.value].some(v => typeof v === 'string')) return 'unknown';
  return 'exposed APIs only';
}

function settingCell(settings, name, risky) {
  const setting = settings && settings[name];
  if (!setting) return '<td></td>';
  const { value, source } = setting;
  const text = value === true ? 'on' : value === false ? 'off' : value;
  const cls = value === risky ? ' class="risk"' : typeof value === 'string' ? ' class="unknown"' : '';
  return `<td${cls}>${escapeHtml(text)}${source === 'default' && typeof value === 'boolean' ? ' <small>default</small>' : ''}</td>`;
}

// What watch mode saw: the pages each window really showed with its settings, IPC use and what was never exercised
function runtimeSurface(runtimeWindows, ipc, coverage, summary, windowCoverage) {
  if (!summary && runtimeWindows.length === 0) return '';
  const unused = coverage[0] && coverage[0].properties ? coverage[0].properties.unusedChannels : [];
  const unopened = windowCoverage[0] && windowCoverage[0].properties ? windowCoverage[0].properties.unopened : [];
  return `
  <h3>Observed while the app ran</h3>${summary ? `
  <p class="note">${escapeHtml(summary.windows)} window(s) and ${escapeHtml(summary.pages)} page load(s) observed; ${escapeHtml(summary.usedChannels)} of ${escapeHtml(summary.channels)} registered IPC channels used.${summary.started ? '' : ' <span class="risk">The app did not load the watch hook: nothing was observed.</span>'}</p>` : ''}${runtimeWindows.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Page</th><th>nodeIntegration</th><th>contextIsolation</th><th>sandbox</th><th>webSecurity</th><th>Preload</th><th>Defined at</th><th>Page script reaches</th></tr></thead>
    <tbody>${runtimeWindows.map(w => { const p = w.properties || {}; return `
      <tr><td class="loc">${escapeHtml(p.url)}</td>${settingCell(p.settings, 'nodeIntegration', true)}${settingCell(p.settings, 'contextIsolation', false)}${settingCell(p.settings, 'sandbox', false)}${settingCell(p.settings, 'webSecurity', false)}<td>${escapeHtml(p.preload || '')}</td><td class="loc">${escapeHtml(p.staticWindow || '')}</td><td>${reach(p.settings)}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${ipc.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>IPC channel used</th><th>By pages from</th></tr></thead>
    <tbody>${ipc.map(i => { const p = i.properties || {}; return `
      <tr><td><code>${escapeHtml(p.channel)}</code></td><td>${escapeHtml((p.senders || []).join(', '))}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${unused.length > 0 ? `
  <p class="note"><b>IPC channels not exercised during the session:</b> ${unused.map(c => `<code>${escapeHtml(c)}</code>`).join(' ')}. Go through the features that use these channels to cover them.</p>` : ''}${unopened.length > 0 ? `
  <p class="note"><b>Windows never opened during the session:</b> ${unopened.map(w => escapeHtml(w)).join('; ')}. Open these screens to observe them at runtime.</p>` : ''}${apiEndpoints(summary)}${entryPoints(summary)}${trafficNote(summary && summary.traffic, 'during the session')}`;
}

// how much traffic the traffic checks saw (in watch mode, or in the saved captures given with --ingest)
function trafficNote(traffic, where) {
  if (!traffic) return '';
  const sources = traffic.sources ? Object.entries(traffic.sources).filter(([, n]) => n > 0).map(([name, n]) => `${escapeHtml(name)} ${escapeHtml(n)}`).join(', ') : '';
  return `
  <p class="note"><b>Traffic checked ${escapeHtml(where)}:</b> ${escapeHtml(traffic.http)} HTTP request(s) and ${escapeHtml(traffic.ws)} WebSocket message(s) to ${escapeHtml(traffic.hosts)} host(s)${traffic.firstParty && traffic.firstParty.length ? `; the app's own domains: ${traffic.firstParty.map(d => `<code>${escapeHtml(d)}</code>`).join(' ')}` : '; the app\'s own domains could not be told (give them with --scope)'}${sources ? ` (sources: ${sources})` : ''}.${(traffic.notes || []).length ? ` ${traffic.notes.map(n => escapeHtml(n)).join('; ')}.` : ''}</p>`;
}

const ENTRY_NAMES = { 'paste-html': 'paste (formatted)', 'paste-text': 'paste (plain text)', 'paste-file': 'paste (file)', 'drop-html': 'drop (formatted)',
  'drop-text': 'drop (text)', 'drop-file': 'drop (file)', 'file-picker': 'file picker', 'open-dialog': 'open dialog', 'open-file': 'file association',
  'open-url': 'deep link', 'second-instance': 'second instance' };

function entryPoints(summary) {
  const used = summary && summary.entryPoints ? Object.entries(summary.entryPoints) : [];
  if (!summary) return '';
  return `
  <p class="note"><b>Ways content came in during the session:</b> ${used.length > 0 ? used.map(([kind, count]) => `${escapeHtml(ENTRY_NAMES[kind] || kind)} &times;${escapeHtml(count)}`).join(', ') : 'none (no paste, drag and drop, file import or deep link)'}.</p>`;
}

// the endpoints pages called: where stored content goes, to test on the server (e.g. with an intercepting proxy)
function apiEndpoints(summary) {
  const api = summary && Array.isArray(summary.api) ? summary.api : [];
  if (api.length === 0) return '';
  const shown = api.slice(0, 100);
  return `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>API endpoint called</th><th>Calls</th><th>Status</th><th>Request body</th></tr></thead>
    <tbody>${shown.map(e => `
      <tr><td class="loc"><code>${escapeHtml(e.method)}</code> ${escapeHtml(e.route)}</td><td>${escapeHtml(e.calls)}</td><td>${escapeHtml(e.statuses.join(', '))}</td><td>${e.htmlBody ? '<span class="risk">contains HTML</span>' : e.maxBodyBytes ? `${escapeHtml(e.maxBodyBytes)} bytes` : ''}</td></tr>`).join('')}
    </tbody>
  </table></div>
  <p class="note">Endpoints that accepted HTML are where stored content enters: check on the server that it is sanitized (or rejected) whatever the client sends.${api.length > shown.length ? ` ${escapeHtml(api.length - shown.length)} more endpoints are in the JSON report.` : ''}</p>`;
}

function attackSurface(windows, apis, runtime = '', hasRuntime = false) {
  if (windows.length === 0 && apis.length === 0 && !runtime) return '';
  return `
  <h2>Renderer attack surface</h2>
  <p class="note">What script running in each window could reach if content the window renders were ever interpreted as code. Values come from the code, or from the defaults of the Electron version in use.</p>${windows.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Window</th><th>Created at</th><th>nodeIntegration</th><th>contextIsolation</th><th>sandbox</th><th>webSecurity</th><th>Preload</th>${hasRuntime ? '<th>Observed at runtime</th>' : ''}<th>Page script reaches</th></tr></thead>
    <tbody>${windows.map(w => { const p = w.properties || {}; return `
      <tr><td>${escapeHtml(p.window)}</td><td class="loc">${escapeHtml(place(w))}</td>${settingCell(p.settings, 'nodeIntegration', true)}${settingCell(p.settings, 'contextIsolation', false)}${settingCell(p.settings, 'sandbox', false)}${settingCell(p.settings, 'webSecurity', false)}<td>${escapeHtml(p.preload || '')}</td>${hasRuntime ? `<td class="loc">${p.observedAt ? escapeHtml(p.observedAt) : '<small>not opened</small>'}</td>` : ''}<td>${reach(p.settings)}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${apis.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Exposed to pages as</th><th>Members</th><th>Defined at</th></tr></thead>
    <tbody>${apis.map(a => { const p = a.properties || {}; return `
      <tr><td>${a.id === 'GLOBAL_EXPOSURE_JS_CHECK' ? escapeHtml(p.world) + ' (direct assignment)' : 'window.' + escapeHtml(p.world)}</td><td>${p.members && p.members.length ? p.members.map(m => `<code>${escapeHtml(m)}</code>`).join(' ') : 'not listed statically'}</td><td class="loc">${escapeHtml(place(a))}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${runtime}`;
}

export function renderHtmlReport(allIssues, meta) {
  const windows = allIssues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK');
  const apis = allIssues.filter(i => i.id === 'EXPOSED_API_JS_CHECK' || i.id === 'GLOBAL_EXPOSURE_JS_CHECK');
  const runtime = runtimeSurface(allIssues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY'), allIssues.filter(i => i.id === 'RUNTIME_IPC'),
    allIssues.filter(i => i.id === 'RUNTIME_COVERAGE'), meta.runtime, allIssues.filter(i => i.id === 'RUNTIME_WINDOW_COVERAGE'));
  const issues = allIssues.filter(i => !INVENTORY.includes(i.id));
  const sorted = [...issues].sort((a, b) =>
    b.severity.value - a.severity.value || b.confidence.value - a.confidence.value ||
    String(a.id).localeCompare(String(b.id)) || String(a.file).localeCompare(String(b.file)) ||
    ((a.location && a.location.line) || 0) - ((b.location && b.location.line) || 0));

  const counts = Object.fromEntries(SEVERITIES.map(s => [s, sorted.filter(i => i.severity.name === s).length]));
  const manual = sorted.filter(i => i.manualReview).length;
  const byCheck = new Map();
  for (const issue of sorted) {
    const entry = byCheck.get(issue.id) || { count: 0, severity: issue.severity };
    entry.count += 1;
    if (issue.severity.value > entry.severity.value) entry.severity = issue.severity;
    byCheck.set(issue.id, entry);
  }
  const errors = (meta.errors || []).filter(e => !e.tolerable);
  const routeCounts = {};
  for (const issue of sorted) {
    const route = (consequenceOf(issue.id) || { route: 'other' }).route;
    routeCounts[route] = (routeCounts[route] || 0) + 1;
  }
  const routeOptions = [...Object.keys(ROUTES), 'other'].filter(r => routeCounts[r])
    .map(r => `<option value="${r}">${escapeHtml(ROUTES[r] || 'Other')} (${routeCounts[r]})</option>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(meta.title || 'Electronegativity report')}</title>
<style>
  :root {
    --bg: #f7f7f8; --panel: #ffffff; --text: #1d1f23; --muted: #5d6470; --border: #dfe2e7; --code: #f1f3f5;
    --high: #c62828; --medium: #d9730d; --low: #b58900; --info: #5d6470; --accent: #2f6fdb;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #15171b; --panel: #1d2026; --text: #e6e8eb; --muted: #9aa3ae; --border: #2e333b; --code: #262a31;
      --high: #ef5350; --medium: #f0883e; --low: #d4b106; --info: #9aa3ae; --accent: #6ea2ff; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 1200px; margin: 0 auto; padding: 24px 16px 48px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 28px 0 12px; }
  .meta { color: var(--muted); display: flex; flex-wrap: wrap; gap: 4px 20px; margin-bottom: 20px; }
  .meta b { color: var(--text); font-weight: 600; overflow-wrap: anywhere; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; border-top: 4px solid var(--border); cursor: pointer; text-align: left; color: inherit; font: inherit; }
  .card .n { font-size: 26px; font-weight: 700; }
  .card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  .card.sev-high { border-top-color: var(--high); } .card.sev-medium { border-top-color: var(--medium); }
  .card.sev-low { border-top-color: var(--low); } .card.sev-informational { border-top-color: var(--info); }
  .card[aria-pressed="false"] { opacity: .45; }
  .checks { display: flex; flex-wrap: wrap; gap: 6px; }
  .checks button { background: var(--panel); border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; color: var(--text); font: inherit; font-size: 12px; cursor: pointer; max-width: 100%; overflow-wrap: anywhere; text-align: left; }
  .checks button.active { border-color: var(--accent); color: var(--accent); }
  .toolbar { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin: 16px 0 10px; }
  .toolbar input[type=search], .toolbar select { background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font: inherit; }
  .toolbar input[type=search] { flex: 1 1 260px; }
  .count { color: var(--muted); }
  .table-wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
  tr:last-child td { border-bottom: 0; }
  .badge { display: inline-block; min-width: 64px; text-align: center; border-radius: 4px; padding: 2px 6px; font-size: 11px; font-weight: 700; color: #fff; }
  .badge.sev-high { background: var(--high); } .badge.sev-medium { background: var(--medium); }
  .badge.sev-low { background: var(--low); } .badge.sev-informational { background: var(--info); }
  .check { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; font-size: 13px; word-break: break-word; }
  .review { font-family: system-ui, sans-serif; font-size: 11px; font-weight: 600; color: var(--medium); border: 1px solid currentColor; border-radius: 4px; padding: 0 4px; margin-left: 4px; }
  .desc { margin: 2px 0 6px; }
  .sample { background: var(--code); border-radius: 6px; padding: 6px 8px; margin: 6px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: 12px; }
  .sample { max-height: 480px; overflow-y: auto; }
  details.code { margin: 4px 0; font-size: 12px; }
  details.code summary { width: fit-content; }
  .cut { color: var(--muted); font-size: 12px; }
  .consequence { margin: 2px 0 6px; padding: 6px 8px; border-left: 3px solid var(--border); background: var(--code); border-radius: 0 6px 6px 0; font-size: 13px; }
  .consequence .interaction { display: block; margin-top: 3px; color: var(--muted); }
  .evidence { font-size: 12px; color: var(--muted); margin: 2px 0 6px; }
  .route { display: inline-block; font-size: 11px; font-weight: 700; border-radius: 4px; padding: 0 6px; margin-right: 4px; border: 1px solid currentColor; white-space: nowrap; }
  .route-content { color: var(--high); } .route-escalation { color: var(--medium); } .route-network { color: var(--accent); }
  .route-local, .route-info, .route-other { color: var(--muted); } .route-dependency { color: var(--low); }
  .route-server, .route-anyone { color: var(--high); } .route-supply { color: var(--medium); } .route-thirdparty { color: var(--medium); }
  .linkish { background: none; border: 0; color: var(--accent); font: inherit; cursor: pointer; padding: 0; }
  .validation { margin: 2px 0 6px; font-size: 13px; padding: 4px 8px; border-radius: 6px; }
  .validation b { margin-right: 4px; }
  .v-confirmed { background: color-mix(in srgb, var(--high) 12%, transparent); } .v-confirmed b { color: var(--high); }
  .v-observed { background: color-mix(in srgb, var(--medium) 12%, transparent); } .v-observed b { color: var(--medium); }
  .v-safe { background: color-mix(in srgb, #2e7d32 12%, transparent); } .v-safe b { color: #2e7d32; }
  details.howto { font-size: 12px; margin: 2px 0 6px; } details.howto div { margin-top: 4px; color: var(--muted); }
  .groups { display: grid; gap: 8px; }
  details.group { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; }
  details.group > summary { cursor: pointer; display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: center; color: var(--text); list-style-position: outside; }
  details.group .gid { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; font-size: 13px; overflow-wrap: anywhere; }
  details.group .gcount { color: var(--muted); font-size: 12px; }
  details.group .gevidence { font-size: 12px; color: var(--muted); }
  details.group dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 10px 0 4px; font-size: 13px; }
  details.group dt { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; padding-top: 2px; }
  details.group dd { margin: 0; }
  details.group ul.where { margin: 0 0 4px; padding-left: 18px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
  .v-confirmed-t { color: var(--high); font-weight: 600; } .v-observed-t { color: var(--medium); } .v-safe-t { color: #2e7d32; }
  button.filter-check.active { font-weight: 600; }
  @media (max-width: 720px) { details.group dl { grid-template-columns: 1fr; } }
  .loc .session { font-family: system-ui, sans-serif; font-size: 11px; font-weight: 600; color: var(--accent); margin-bottom: 2px; }
  .muted { color: var(--muted); font-size: 12px; }
  .mono, .deps .pkg { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
  .nowrap { white-space: nowrap; font-size: 12px; }
  .deps td { font-size: 13px; }
  .deps .files { overflow-wrap: anywhere; max-width: 260px; }
  .support { font-weight: 600; font-size: 12px; white-space: nowrap; }
  .support-unsupported { color: var(--high); } .support-outdated { color: var(--medium); } .support-unknown { color: var(--muted); }
  .support-supported, .support-current { color: #2e7d32; }
  .adv { font-size: 11px; font-weight: 700; border-radius: 4px; padding: 0 5px; white-space: nowrap; border: 1px solid currentColor; }
  .adv-critical, .adv-high { color: var(--high); } .adv-medium { color: var(--medium); } .adv-low { color: var(--low); } .adv-unrated { color: var(--muted); }
  .refs { font-size: 11px; margin-top: 2px; font-family: system-ui, sans-serif; } .refs a { color: var(--accent); }
  .advlist { margin: 6px 0 0; padding-left: 18px; min-width: 280px; } .advlist li { margin-bottom: 4px; font-size: 12px; }
  .depsummary { display: flex; flex-wrap: wrap; gap: 6px 20px; margin: 4px 0; color: var(--muted); } .depsummary b { color: var(--text); }
  .loc { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; min-width: 180px; }
  .pos { white-space: nowrap; }
  details summary { cursor: pointer; color: var(--accent); }
  .conf { font-size: 12px; color: var(--muted); }
  a { color: var(--accent); }
  .ref, .advisories { font-size: 12px; }
  .empty { padding: 32px; text-align: center; color: var(--muted); }
  .errors li { font-family: ui-monospace, monospace; font-size: 12px; margin-bottom: 4px; word-break: break-word; }
  footer { margin-top: 32px; color: var(--muted); font-size: 12px; }
  @media (max-width: 720px) {
    .table-wrap { background: none; border: 0; }
    thead { display: none; }
    table, tbody, tr, td { display: block; width: 100%; }
    tr.finding { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; padding: 4px 0; }
    tr.finding[hidden], tr.dep[hidden] { display: none; }
    td { border: 0; padding: 4px 12px; }
    .loc { min-width: 0; }
  }
  .surface td.risk, .surface .risk { color: var(--high, #c62828); font-weight: 600; }
  .surface td.unknown { color: var(--muted, #777); font-style: italic; }
  .surface small { color: var(--muted, #777); }
  .note { color: var(--muted, #777); font-size: 13px; margin: 0 0 8px; }
  .table-wrap + .table-wrap, .table-wrap + .note { margin-top: 12px; }
  @media print { .toolbar, .checks { display: none; } .card { cursor: default; } body { background: #fff; } }
</style>
</head>
<body>
<main>
  <h1>${escapeHtml(meta.title || 'Electronegativity report')}</h1>
  <div class="meta">
    <span>Target: <b>${escapeHtml(meta.installer ? meta.installer.file : meta.input)}</b>${meta.installer ? ` (${escapeHtml(meta.installer.kind)}, SHA-256 ${escapeHtml(meta.installer.sha256)}; the app inside was unpacked to ${escapeHtml(meta.input)})` : ''}</span>
    <span>Electron: <b>${escapeHtml(meta.electronVersion || 'not detected (oldest defaults assumed)')}</b>${bundledText(meta.dependencies && meta.dependencies.bundled)}</span>
    <span>Files scanned: <b>${escapeHtml(meta.filesScanned)}</b></span>
    <span>Checks: <b>${escapeHtml(meta.atomicChecks)}</b> atomic, <b>${escapeHtml(meta.globalChecks)}</b> global</span>
    <span>Generated: <b>${escapeHtml(meta.generatedAt)}</b></span>${meta.suppressedByBaseline ? `
    <span>Accepted in baseline: <b>${escapeHtml(meta.suppressedByBaseline)}</b></span>` : ''}${meta.binary ? `
    <span>Executable: <b>${escapeHtml(meta.binary.executable.split(/[\\/]/).pop())}</b>${meta.binary.signing ? ` (signature: ${escapeHtml(meta.binary.signing.status)}${meta.binary.signing.verifiedBy === 'none' && meta.binary.signing.status !== 'NotSigned' ? ', not verified on this host' : ''})` : ''}${meta.binary.integrity ? `, asar integrity: ${escapeHtml(meta.binary.integrity)}` : ''}${meta.binary.mitigations && meta.binary.mitigations.missing.length ? `, missing mitigations: ${escapeHtml(meta.binary.mitigations.missing.join(', '))}` : ''}</span>` : ''}
  </div>

  <div class="cards" role="group" aria-label="Filter by severity">
${SEVERITIES.map(s => `    <button type="button" class="card sev-${s.toLowerCase()}" data-sev="${s}" aria-pressed="true"><div class="n">${counts[s]}</div><div class="l">${s === 'INFORMATIONAL' ? 'Info' : s.toLowerCase()}</div></button>`).join('\n')}
    <div class="card"><div class="n">${manual}</div><div class="l">Need manual review</div></div>
    <div class="card" title="Every distinct finding, weighted by severity and confidence, with diminishing returns"><div class="n">${scores(issues).risk}</div><div class="l">Risk score</div></div>
    <div class="card" title="Only what someone other than the user can exploit: shared content, anyone with the app, the network, other users through the server, third parties, the supply chain, known vulnerabilities"><div class="n">${scores(issues).external}</div><div class="l">External-only score</div></div>
  </div>

${meta.extraSections || ''}
${attackSurface(windows, apis, runtime, !!meta.runtime)}${meta.traffic ? `
  <h2>Captured traffic</h2>${trafficNote(meta.traffic, `in ${meta.traffic.files} capture file(s)`)}` : ''}${savedCredentials(allIssues.filter(i => i.id === 'CREDENTIAL_ACCESS_JS_CHECK'), meta.atRest)}
  <h2>Findings by type (${byCheck.size})</h2>
  <p class="note">Each type of finding once: what it is, what it implies and its impact, with where it was found. Open one for details; "Show these findings" filters the list below.</p>
  <div class="groups">${findingGroups(sorted).map(groupCard).join('')}
  </div>

  <h2 id="findings">Findings</h2>
  <div class="toolbar">
    <input type="search" id="search" placeholder="Filter by check, file, description or code" aria-label="Filter findings">
    <label>Confidence <select id="confidence">
      <option value="0">Any</option>${CONFIDENCES.slice(0, 2).map((c, i) => `<option value="${2 - i}">${c}${i === 0 ? '' : ' or higher'}</option>`).join('')}
    </select></label>
    <label>Exploitable by <select id="route">
      <option value="">Anyone</option>${routeOptions}
    </select></label>
    <label>Validation <select id="validation">
      <option value="">Any</option><option value="confirmed">Confirmed at runtime</option><option value="observed">Seen at runtime</option><option value="safe">Ruled out at runtime</option><option value="open">Needs review, not validated</option>
    </select></label>
    <label><input type="checkbox" id="manual"> Manual review only</label>${meta.comparison ? `
    <label><input type="checkbox" id="onlynew"> New since the previous scan only</label>` : ''}
    <button type="button" id="expand" class="linkish">Expand all code</button>
    <span class="count" id="count"></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Confidence</th></tr></thead>
      <tbody>${sorted.map(findingRow).join('')}
      </tbody>
    </table>
    <div class="empty" id="empty"${sorted.length === 0 ? '' : ' hidden'}>${sorted.length === 0 ? 'No issues found.' : 'No findings match the current filters.'}</div>
  </div>
${triageSection(meta)}
${dependencySection(meta.dependencies)}
${errors.length > 0 ? `
  <h2>Files that could not be analyzed (${errors.length})</h2>
  <ul class="errors">${errors.map(e => `<li>${escapeHtml(e.file)}: ${escapeHtml(e.message)}</li>`).join('')}</ul>` : ''}
  <footer>Generated by Electronegativity ${escapeHtml(meta.version)}. Findings marked "review" need a manual assessment; absence of findings does not prove the absence of vulnerabilities.</footer>
</main>
<script>
(() => {
  const confidenceValue = { CERTAIN: 2, FIRM: 1, TENTATIVE: 0 };
  const rows = [...document.querySelectorAll('tr.finding')];
  const cards = [...document.querySelectorAll('.card[data-sev]')];
  const checkButtons = [...document.querySelectorAll('button.filter-check')];
  const search = document.getElementById('search');
  const confidence = document.getElementById('confidence');
  const manual = document.getElementById('manual');
  const route = document.getElementById('route');
  const validation = document.getElementById('validation');
  const expand = document.getElementById('expand');
  const onlyNew = document.getElementById('onlynew');
  let activeCheck = null;

  function apply() {
    const severities = new Set(cards.filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.dataset.sev));
    const q = search.value.trim().toLowerCase();
    const minConfidence = Number(confidence.value);
    let visible = 0;
    for (const row of rows) {
      const show = severities.has(row.dataset.severity) &&
        confidenceValue[row.dataset.confidence] >= minConfidence &&
        (!manual.checked || row.dataset.manual === '1') &&
        (!route.value || row.dataset.route === route.value) &&
        (!validation.value || row.dataset.validation === validation.value) &&
        (!onlyNew || !onlyNew.checked || row.dataset.new === '1') &&
        (!activeCheck || row.dataset.check === activeCheck) &&
        (!q || row.dataset.text.includes(q));
      row.hidden = !show;
      if (show) visible++;
    }
    document.getElementById('count').textContent = visible + ' of ' + rows.length + ' findings';
    if (rows.length) document.getElementById('empty').hidden = visible > 0;
  }

  cards.forEach(card => card.addEventListener('click', () => {
    card.setAttribute('aria-pressed', card.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
    apply();
  }));
  checkButtons.forEach(button => button.addEventListener('click', () => {
    activeCheck = activeCheck === button.dataset.check ? null : button.dataset.check;
    checkButtons.forEach(b => {
      const active = b.dataset.check === activeCheck;
      if (!b.dataset.label) b.dataset.label = b.textContent;
      b.classList.toggle('active', active);
      b.textContent = active ? 'Showing only these below (click to show all)' : b.dataset.label;
    });
    apply();
    if (activeCheck) document.getElementById('findings').scrollIntoView({ behavior: 'smooth' });
  }));
  [search, confidence, manual, route, validation, onlyNew].filter(Boolean).forEach(el => el.addEventListener('input', apply));
  const depRows = [...document.querySelectorAll('tr.dep')];
  const depSearch = document.getElementById('depsearch');
  const depIssues = document.getElementById('depissues');
  function applyDeps() {
    const q = depSearch.value.trim().toLowerCase();
    let visible = 0;
    for (const row of depRows) {
      row.hidden = !((!depIssues.checked || row.dataset.issue === '1') && (!q || row.dataset.text.includes(q)));
      if (!row.hidden) visible++;
    }
    document.getElementById('depcount').textContent = visible + ' of ' + depRows.length + ' packages';
  }
  if (depSearch) {
    [depSearch, depIssues].forEach(el => el.addEventListener('input', applyDeps));
    applyDeps();
  }
  expand.addEventListener('click', () => {
    const open = expand.textContent.startsWith('Expand');
    document.querySelectorAll('tr.finding:not([hidden]) details.code').forEach(d => { d.open = open; });
    expand.textContent = open ? 'Collapse all code' : 'Expand all code';
  });
  apply();
})();
</script>
</body>
</html>
`;
}
