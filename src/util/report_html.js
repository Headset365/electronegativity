// Self-contained HTML report: no external resources, so it can be archived, attached to tickets or opened offline.
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

function findingRow(issue, index) {
  const sev = issue.severity.name;
  const conf = issue.confidence.name;
  const position = issue.file !== 'N/A' && issue.location && issue.location.line ? `:${issue.location.line}:${issue.location.column}` : '';
  const location = issue.file === 'N/A' ? 'Application-wide' : issue.file;
  const url = safeUrl(issue.shortenedURL);
  const advisories = issue.properties && Array.isArray(issue.properties.advisories) ? issue.properties.advisories : undefined;
  const searchText = [issue.id, issue.file, issue.description, issue.sample].join(' ').toLowerCase();

  return `
      <tr class="finding" data-severity="${sev}" data-confidence="${conf}" data-check="${escapeHtml(issue.id)}" data-manual="${issue.manualReview ? 1 : 0}" data-text="${escapeHtml(searchText)}" data-index="${index}">
        <td><span class="badge sev-${sev.toLowerCase()}">${sev === 'INFORMATIONAL' ? 'INFO' : sev}</span></td>
        <td>
          <div class="check">${escapeHtml(issue.id)}${issue.manualReview ? ' <span class="review" title="Requires manual review">review</span>' : ''}</div>
          <div class="desc">${escapeHtml(issue.description)}</div>
          ${issue.sample ? `<pre class="sample"><code>${escapeHtml(issue.sample)}</code></pre>` : ''}
          ${advisories ? `<div class="advisories">${advisoryLinks(advisories)}</div>` : ''}
          ${url ? `<a class="ref" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Reference</a>` : ''}
        </td>
        <td class="loc">${escapeHtml(location)}<span class="pos">${escapeHtml(position)}</span></td>
        <td><span class="conf">${conf}</span></td>
      </tr>`;
}

/**
 * @param {Array} issues findings, as returned by run()
 * @param {Object} meta { version, input, electronVersion, filesScanned, globalChecks, atomicChecks, errors, generatedAt }
 */
const INVENTORY = ['WINDOW_SUMMARY_JS_CHECK', 'EXPOSED_API_JS_CHECK'];
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

function attackSurface(windows, apis) {
  if (windows.length === 0 && apis.length === 0) return '';
  return `
  <h2>Renderer attack surface</h2>
  <p class="note">What script running in each window could reach if content the window renders were ever interpreted as code. Values come from the code, or from the defaults of the Electron version in use.</p>${windows.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Window</th><th>Created at</th><th>nodeIntegration</th><th>contextIsolation</th><th>sandbox</th><th>webSecurity</th><th>Preload</th><th>Page script reaches</th></tr></thead>
    <tbody>${windows.map(w => { const p = w.properties || {}; return `
      <tr><td>${escapeHtml(p.window)}</td><td class="loc">${escapeHtml(place(w))}</td>${settingCell(p.settings, 'nodeIntegration', true)}${settingCell(p.settings, 'contextIsolation', false)}${settingCell(p.settings, 'sandbox', false)}${settingCell(p.settings, 'webSecurity', false)}<td>${escapeHtml(p.preload || '')}</td><td>${reach(p.settings)}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}${apis.length > 0 ? `
  <div class="table-wrap"><table class="surface">
    <thead><tr><th>Exposed to pages as</th><th>Members</th><th>Defined at</th></tr></thead>
    <tbody>${apis.map(a => { const p = a.properties || {}; return `
      <tr><td>window.${escapeHtml(p.world)}</td><td>${p.members && p.members.length ? p.members.map(m => `<code>${escapeHtml(m)}</code>`).join(' ') : 'not listed statically'}</td><td class="loc">${escapeHtml(place(a))}</td></tr>`; }).join('')}
    </tbody>
  </table></div>` : ''}`;
}

export function renderHtmlReport(allIssues, meta) {
  const windows = allIssues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK');
  const apis = allIssues.filter(i => i.id === 'EXPOSED_API_JS_CHECK');
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

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Electronegativity report</title>
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
    tr.finding[hidden] { display: none; }
    td { border: 0; padding: 4px 12px; }
    .loc { min-width: 0; }
  }
  .surface td.risk, .surface .risk { color: var(--high, #c62828); font-weight: 600; }
  .surface td.unknown { color: var(--muted, #777); font-style: italic; }
  .surface small { color: var(--muted, #777); }
  .note { color: var(--muted, #777); font-size: 13px; margin: 0 0 8px; }
  @media print { .toolbar, .checks { display: none; } .card { cursor: default; } body { background: #fff; } }
</style>
</head>
<body>
<main>
  <h1>Electronegativity report</h1>
  <div class="meta">
    <span>Target: <b>${escapeHtml(meta.input)}</b></span>
    <span>Electron: <b>${escapeHtml(meta.electronVersion || 'not detected (oldest defaults assumed)')}</b></span>
    <span>Files scanned: <b>${escapeHtml(meta.filesScanned)}</b></span>
    <span>Checks: <b>${escapeHtml(meta.atomicChecks)}</b> atomic, <b>${escapeHtml(meta.globalChecks)}</b> global</span>
    <span>Generated: <b>${escapeHtml(meta.generatedAt)}</b></span>${meta.suppressedByBaseline ? `
    <span>Accepted in baseline: <b>${escapeHtml(meta.suppressedByBaseline)}</b></span>` : ''}
  </div>

  <div class="cards" role="group" aria-label="Filter by severity">
${SEVERITIES.map(s => `    <button type="button" class="card sev-${s.toLowerCase()}" data-sev="${s}" aria-pressed="true"><div class="n">${counts[s]}</div><div class="l">${s === 'INFORMATIONAL' ? 'Info' : s.toLowerCase()}</div></button>`).join('\n')}
    <div class="card"><div class="n">${manual}</div><div class="l">Need manual review</div></div>
  </div>

${attackSurface(windows, apis)}
  <h2>Findings by check</h2>
  <div class="checks">
${[...byCheck.entries()].map(([id, e]) => `    <button type="button" data-check="${escapeHtml(id)}"><span class="badge sev-${e.severity.name.toLowerCase()}" style="min-width:0">${e.count}</span> ${escapeHtml(id)}</button>`).join('\n')}
  </div>

  <h2>Findings</h2>
  <div class="toolbar">
    <input type="search" id="search" placeholder="Filter by check, file, description or code" aria-label="Filter findings">
    <label>Confidence <select id="confidence">
      <option value="0">Any</option>${CONFIDENCES.slice(0, 2).map((c, i) => `<option value="${2 - i}">${c}${i === 0 ? '' : ' or higher'}</option>`).join('')}
    </select></label>
    <label><input type="checkbox" id="manual"> Manual review only</label>
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
  const checkButtons = [...document.querySelectorAll('.checks button')];
  const search = document.getElementById('search');
  const confidence = document.getElementById('confidence');
  const manual = document.getElementById('manual');
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
    checkButtons.forEach(b => b.classList.toggle('active', b.dataset.check === activeCheck));
    apply();
  }));
  [search, confidence, manual].forEach(el => el.addEventListener('input', apply));
  apply();
})();
</script>
</body>
</html>
`;
}
