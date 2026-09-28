// The Word (.docx) report, for delivering an assessment: findings grouped by who can exploit them, each check with its
// severity, the affected files and hosts, the implication, evidence, how to reproduce or validate it, the recommendation
// and references; the saved-credential results; and Appendix A listing outdated, unsupported and vulnerable components.
// Your --finding-notes fill in implication, reproduction steps and recommendations. Written with `-o report.docx`.
// Modelled on Electron-Dynamic's report/docx_report.py.
import { Doc } from './ooxml.js';
import { ROUTES, consequenceOf, validationHint, interactionOf } from '../finder/consequences.js';
import { scores } from './scores.js';

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const COLORS = { HIGH: 'C00000', MEDIUM: 'E26B0A', LOW: 'BF8F00', INFORMATIONAL: '595959' };
// inventory, shown as tables rather than findings
const INVENTORY = new Set(['WINDOW_SUMMARY_JS_CHECK', 'EXPOSED_API_JS_CHECK', 'GLOBAL_EXPOSURE_JS_CHECK', 'RUNTIME_WINDOW_SUMMARY', 'RUNTIME_IPC', 'RUNTIME_COVERAGE', 'RUNTIME_WINDOW_COVERAGE',
  'CREDENTIAL_ACCESS_JS_CHECK', 'DEPENDENCY_INVENTORY_LOCK_CHECK']);
const ROUTE_ORDER = ['content', 'anyone', 'network', 'server', 'thirdparty', 'supply', 'escalation', 'local', 'dependency', 'info', 'other'];
const APPENDIX = 'AppendixA';

const place = (issue) => `${issue.file}${issue.location && issue.location.line ? `:${issue.location.line}` : ''}`;

function titleOf(id, issues) {
  const text = typeof __ === 'function' ? __(id) : id;
  if (text && text !== id) return text;
  const first = String(issues[0].description || id);
  return first.split(/[:(]/)[0].slice(0, 100).trim() || id;
}

/** Findings grouped by route, then by check: [[route, [{ id, title, issues, severity, confidence }]]] */
export function groupFindings(issues) {
  const byCheck = new Map();
  for (const issue of issues) {
    if (INVENTORY.has(issue.id) || issue.severity.name === 'INFORMATIONAL') continue;
    byCheck.set(issue.id, [...(byCheck.get(issue.id) || []), issue]);
  }
  const groups = [...byCheck.entries()].map(([id, list]) => {
    list.sort((a, b) => b.severity.value - a.severity.value || b.confidence.value - a.confidence.value);
    return { id, title: titleOf(id, list), issues: list, severity: list[0].severity, confidence: list[0].confidence, route: (consequenceOf(id) || { route: 'other' }).route };
  }).sort((a, b) => b.severity.value - a.severity.value || b.confidence.value - a.confidence.value || a.id.localeCompare(b.id));
  const byRoute = new Map();
  for (const group of groups) byRoute.set(group.route, [...(byRoute.get(group.route) || []), group]);
  return ROUTE_ORDER.filter(route => byRoute.has(route)).map(route => [route, byRoute.get(route)]);
}

// the components for Appendix A: the Electron runtime and every outdated, unsupported or vulnerable package
export function appendixRows(dependencies) {
  const rows = (dependencies && dependencies.rows) || [];
  return rows.filter(r => r.name === 'electron' || r.advisories.length > 0 || ['unsupported', 'outdated'].includes(r.support.status) || r.versionsBehind > 0 || r.malicious)
    .map(r => ({ ...r, status: [r.malicious ? 'malicious' : '', r.advisories.length ? `vulnerable (${r.advisories.length} advisories${r.kev ? ', exploited in the wild' : ''})` : '',
      r.support.status === 'unsupported' ? 'unsupported / end of life' : r.support.status === 'outdated' ? 'outdated' : r.versionsBehind > 0 ? 'not the latest version' : ''].filter(Boolean).join('; ') || 'current' }));
}

function bulletsOrText(doc, value) {
  if (Array.isArray(value)) for (const item of value) doc.bullet(String(item));
  else doc.para(String(value));
}

function renderGroup(doc, group, number, appendixIndex) {
  doc.heading(`${number} ${group.title}`, 2);
  const consequence = consequenceOf(group.id);
  doc.table(['Severity', 'Confidence', 'Exploitable by', 'Instances', 'Check'], [[
    [doc.run(group.severity.name, { bold: true, color: COLORS[group.severity.name] })], group.confidence.name, consequence ? consequence.label : 'Other', String(group.issues.length), group.id]],
  { widths: [1.1, 1.1, 1.6, 0.9, 2.6] });
  const notes = group.issues.find(i => i.notes) ? group.issues.find(i => i.notes).notes : undefined;

  doc.label('Issue description');
  doc.para(group.issues[0].description);
  if (notes && notes.about) bulletsOrText(doc, notes.about);

  doc.label('Affected hosts, endpoints and files');
  const affected = [...new Set(group.issues.map(place))];
  for (const item of affected.slice(0, 25)) doc.bullet(doc.run(item, { mono: true }));
  if (affected.length > 25) doc.para(doc.run(`…and ${affected.length - 25} more (see the HTML or JSON report).`, { italic: true }));
  const related = group.issues.flatMap(i => (i.properties && i.properties.packages) || []).map(p => appendixIndex.get(`${p.name}@${p.version}`)).filter(Boolean);
  if (related.length > 0) doc.para([doc.run('Components: '), ...[...new Set(related)].map((ref, i) => [i ? doc.run(', ') : '', doc.anchorLink(ref, APPENDIX)]).flat().filter(Boolean)]);

  doc.label('Implication');
  if (notes && notes.impact) bulletsOrText(doc, notes.impact);
  else doc.para(consequence ? consequence.text : 'See the reference below.');
  if (notes && notes.reachability) bulletsOrText(doc, notes.reachability);
  if (interactionOf(group.id) && (!consequence || consequence.route !== 'info')) doc.para([doc.run('Victim interaction: ', { bold: true }), doc.run(interactionOf(group.id))]);

  doc.label('Evidence and reproduction');
  for (const issue of group.issues.slice(0, 5)) {
    doc.para(doc.run(`${place(issue)}: ${issue.description}${issue.properties && issue.properties.screenshot ? ` (screenshot: ${issue.properties.screenshot})` : ''}`, { size: 9 }));
    if (issue.sample) doc.code(issue.sample);
    for (const line of ((issue.properties && issue.properties.evidence) || []).slice(1, 4)) doc.code(line);
    if (issue.validation) doc.para(doc.run(issue.validation.text, { italic: true }));
  }
  if (notes && notes.preconditions) {
    doc.para(doc.run('Preconditions', { bold: true }));
    bulletsOrText(doc, notes.preconditions);
  }
  if (notes && notes.steps) {
    doc.para(doc.run('Steps', { bold: true }));
    bulletsOrText(doc, notes.steps);
  }
  const hint = (notes && notes.confirm) || validationHint(group.id);
  if (hint) bulletsOrText(doc, hint);

  doc.label('Recommendations');
  if (notes && notes.recommendation) bulletsOrText(doc, notes.recommendation);
  else doc.para([doc.run('Follow the guidance at '), doc.link(group.issues[0].shortenedURL, group.issues[0].shortenedURL), doc.run('.')]);

  doc.label('References');
  const references = [...new Set(group.issues.map(i => i.shortenedURL).filter(Boolean))];
  for (const url of references.slice(0, 10)) doc.bullet(doc.link(url, url));
}

function renderCredentials(doc, issues, atRest, number) {
  const rows = issues.filter(i => i.id === 'CREDENTIAL_ACCESS_JS_CHECK');
  const trace = atRest && atRest.credentialTrace;
  if (rows.length === 0 && !trace) return false;
  doc.heading(`${number}. Saved credentials`, 1);
  if (trace) {
    doc.heading(`${number}.1 Where the saved password went`, 2);
    doc.para(trace.locations.length > 0 ? `The test password was found in ${trace.locations.length} location(s), unencrypted:` : 'The test password was not found in plaintext or a common encoding.');
    for (const location of trace.locations) doc.bullet(doc.run(location, { mono: true }));
    doc.para(`${trace.files} files and ${trace.leveldbStores} LevelDB stores were searched under ${trace.roots.join(', ')}.`);
    if (trace.credentialManagerNew.length) doc.para(`New Windows Credential Manager entries: ${trace.credentialManagerNew.join(', ')}.`);
  }
  if (rows.length > 0) {
    doc.heading(`${number}.${trace ? 2 : 1} Credential storage in code`, 2);
    const protection = (p) => p === true ? 'OS-protected' : p === false ? 'not protected' : 'check';
    doc.table(['Operation', 'API', 'Store', 'Protection', 'At'], rows.slice(0, 200).map(r => [r.properties.op, r.properties.api, r.properties.store, protection(r.properties.protected), place(r)]),
      { widths: [0.9, 1.6, 2.4, 1.1, 2.2], fontSize: 8 });
  }
  return true;
}

function renderAppendix(doc, rows) {
  doc.pageBreak();
  doc.heading('Appendix A – Third-party component versions', 1, APPENDIX);
  if (rows.length === 0) {
    doc.para('No outdated, unsupported or vulnerable components were found (or the versions were not looked up: --offline).');
    return;
  }
  doc.table(['#', 'Library', 'Version found (released)', 'Status', 'Current version (released)', 'Found at'], rows.map((r, i) => [
    `A-${i + 1}`, r.name, `${r.version}${r.released ? ` (${r.released})` : ''}`,
    [doc.run(r.status), ...r.advisories.slice(0, 5).map(a => [doc.run('\n'), doc.link([...(a.cves || []), a.id][0], `https://osv.dev/vulnerability/${a.id}`)]).flat()],
    r.latest ? [doc.link(`${r.latest}${r.latestReleased ? ` (${r.latestReleased})` : ''}`, r.name === 'electron' ? `https://releases.electronjs.org/release/v${r.latest}` : `https://www.npmjs.com/package/${r.name}/v/${r.latest}`)] : '?',
    (r.files && r.files.length ? r.files.slice(0, 2).join(', ') : r.kinds.join(', ')),
  ]), { widths: [0.5, 1.4, 1.4, 2.2, 1.5, 1.8], fontSize: 8 });
}

/** The report as a .docx Buffer. */
export function renderDocx(issues, meta) {
  const app = meta.app || {};
  const doc = new Doc(`Electronegativity report${app.name ? `: ${app.name}` : ''}`);
  doc.para(doc.run(`Electron security assessment${app.name ? `: ${app.name}${app.version ? ` ${app.version}` : ''}` : ''}`), { style: 'Title' });
  doc.para(`Target: ${meta.installer ? meta.installer.file : meta.input}`);
  const bundled = meta.dependencies && meta.dependencies.bundled;
  const runtimes = bundled ? [['Chromium', bundled.chromium], ['Node.js', bundled.node], ['V8', bundled.v8], ['OpenSSL', bundled.openssl]].filter(([, v]) => v).map(([k, v]) => `${k} ${v}`).join(', ') : '';
  doc.para(`Electron: ${meta.electronVersion || 'not detected'}${runtimes ? ` (${runtimes})` : ''} · Generated ${meta.generatedAt} by Electronegativity ${meta.version}`);
  doc.heading('Contents', 1);
  doc.toc();
  doc.pageBreak();

  const appendix = appendixRows(meta.dependencies);
  const appendixIndex = new Map(appendix.map((r, i) => [`${r.name}@${r.version}`, `A-${i + 1}`]));
  const groups = groupFindings(issues);
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, issues.filter(i => i.severity.name === s && !INVENTORY.has(i.id)).length]));
  const { risk, external } = scores(issues);

  doc.heading('1. Summary', 1);
  doc.table(['High', 'Medium', 'Low', 'Informational', 'Risk score', 'External-only score'], [[String(counts.HIGH), String(counts.MEDIUM), String(counts.LOW), String(counts.INFORMATIONAL), `${risk}/100`, `${external}/100`]]);
  doc.para('The risk score combines every distinct finding (weighted by severity and confidence, with diminishing returns); the external-only score counts only what someone other than the user can exploit: shared content, anyone with the app, the network, other users through the server, third parties, the supply chain and known vulnerabilities.');
  const high = groups.flatMap(([, list]) => list).filter(g => g.severity.name === 'HIGH');
  if (high.length) {
    doc.para(doc.run('High-severity findings', { bold: true }));
    for (const g of high.slice(0, 20)) doc.bullet(`${g.title} (${g.issues.length})`);
  }

  let number = 2;
  for (const [route, list] of groups) {
    doc.heading(`${number}. ${ROUTES[route] || 'Other'}`, 1);
    list.forEach((group, i) => renderGroup(doc, group, `${number}.${i + 1}`, appendixIndex));
    number++;
  }
  if (renderCredentials(doc, issues, meta.atRest, number)) number++;
  const chromium = meta.dependencies && meta.dependencies.chromium;
  if (chromium && chromium.checked) {
    doc.heading(`${number}. Chromium advisories`, 1);
    doc.para(`The Chromium ${chromium.chromium} in this Electron version misses ${chromium.total} upstream security fixes, ${chromium.kev} of them for vulnerabilities exploited in the wild (CISA KEV)${chromium.backportsChecked ? `; ${chromium.backported} fixes Electron backported into this version are not counted` : ''}.`);
    doc.table(['CVE', 'Severity', 'Fixed in Chromium', 'First Electron with the fix'], chromium.top.map(r => [[doc.link(`${r.id}${r.kev ? ' (KEV)' : ''}`, `https://nvd.nist.gov/vuln/detail/${r.id}`)], r.severity, r.fixedIn || '?', r.electronFix || '?']), { widths: [2, 1, 1.5, 1.5] });
  }
  renderAppendix(doc, appendix);
  return doc.toBuffer();
}
