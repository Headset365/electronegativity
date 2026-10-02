// The components workbook (-o components.xlsx) that the client report's "Outdated Third-Party Components" finding refers
// to. Sheet 1, "Components needing action": one row per component that is outdated, unsupported, end of life, malicious or
// has known advisories, with its status, what to do and links to its version pages and advisories. Sheet 2, "All
// components": every component found, its version and where it was found. Written as SpreadsheetML with the zip writer
// of the Word report, no dependencies.
import { zipFiles, xmlText } from './ooxml.js';
import { npmUrl } from '../util/dependency_references.js';

const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, MODERATE: 2, LOW: 1 };

const isElectron = (row) => row.name === 'electron';
const typeOf = (row) => isElectron(row) ? 'Electron runtime'
  : (row.kinds || []).length > 0 && (row.kinds || []).every(kind => kind === 'bundled library') ? 'JS library' : 'npm package';

// a newer release than the installed one exists (a prerelease newer than the latest is not behind)
const behind = (row) => !!(row.latest && row.version && row.latest !== row.version && (row.versionsBehind === undefined || row.versionsBehind > 0));

/**
 * The support status labels of a component, in this order: Malicious; Latest or Outdated; Unsupported (its version line
 * is past its support end) or End of life (the whole package is no longer maintained); Known advisories. Unknown when
 * the registry and support data were not available.
 */
export function statusLabels(row) {
  const labels = [];
  const support = (row.support && row.support.status) || 'unknown';
  // deprecated as a whole on npm (the latest release too), or every release line past its end of life
  const ended = !!(row.latestDeprecated || (row.support && row.support.discontinued));
  const unsupported = !ended && support === 'unsupported';
  if (row.malicious) labels.push('Malicious');
  if (row.latest && row.version === row.latest) labels.push('Latest');
  else if (behind(row) && !ended && !unsupported) labels.push('Outdated');
  if (ended) labels.push('End of life');
  if (unsupported) labels.push('Unsupported');
  if ((row.advisories || []).length > 0) labels.push('Known advisories');
  if (labels.length === 0) labels.push(row.latest ? 'Latest' : 'Unknown');
  return labels;
}

/** Components that need action: anything but Latest (or Unknown, when nothing could be looked up). */
export function needsAction(row) {
  return statusLabels(row).some(label => label !== 'Latest' && label !== 'Unknown');
}

function action(row, labels) {
  const latest = row.latest;
  if (row.malicious) return `Remove immediately: known malicious version (${row.malicious.id})`;
  if (labels.includes('End of life')) return `Replace with a maintained alternative: ${row.name} is no longer maintained`;
  if (labels.includes('Unsupported')) return `Upgrade to a supported release line${latest ? ` (latest ${latest})` : ''}`;
  if ((row.advisories || []).length > 0) {
    if (row.fixedIn) return `Upgrade to ${row.fixedIn} or later${latest && latest !== row.fixedIn ? ` (latest ${latest})` : ''}`;
    // some advisory has no fixed version
    if (latest && behind(row)) return `Upgrade to ${latest}, then review the advisories: some have no fixed version`;
    return `Review the advisories: some have no fixed version; consider replacing ${row.name}`;
  }
  if (labels.includes('Outdated')) return `Upgrade to ${latest}`;
  return 'Review';
}

// the page of one version: Electron's release notes, or the npm page of the package version
const versionPage = (row, version) => isElectron(row) ? `https://releases.electronjs.org/release/v${encodeURIComponent(version)}` : npmUrl(row.name, version);
const versionLabel = (row, version) => isElectron(row) ? `Electron ${version} release notes` : `npm: ${row.name} ${version}`;

/** The five links of a component: its installed and latest version pages, and its advisories on deps.dev, Snyk and GitHub. */
export function componentLinks(row) {
  const name = encodeURIComponent(row.name);
  const version = encodeURIComponent(row.version);
  return [
    // a version npm doesn't know (a library copy with its own numbering): the package page
    row.known === false && !isElectron(row) ? { url: npmUrl(row.name), text: `npm: ${row.name} (version not on npm)` } : { url: versionPage(row, row.version), text: versionLabel(row, row.version) },
    row.latest ? { url: versionPage(row, row.latest), text: versionLabel(row, row.latest) } : undefined,
    { url: `https://deps.dev/npm/${name}/${version}`, text: `deps.dev: ${row.name} ${row.version}` },
    { url: `https://security.snyk.io/package/npm/${name}/${version}`, text: `Snyk: ${row.name} ${row.version}` },
    { url: `https://github.com/advisories?query=${encodeURIComponent(`ecosystem:npm affects:${row.name}`)}`, text: `GitHub: all advisories for ${row.name} (every version)` },
  ];
}

// an Excel date (days since 1899-12-30) for YYYY-MM-DD, so the column sorts and filters as dates
function excelDate(text) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text || '');
  return match ? (Date.UTC(+match[1], +match[2] - 1, +match[3]) - Date.UTC(1899, 11, 30)) / 86400000 : '';
}

const date = (text) => ({ value: excelDate(text), style: excelDate(text) === '' ? undefined : DATE });
const link = (target) => target ? { value: target.text, url: target.url } : '';

export const ACTION_HEADER = ['Component', 'Type', 'Installed version', 'Installed version release date', 'Latest version', 'Latest version release date',
  'Support status', 'Recommended action', 'Path found', 'Installed version link', 'Latest version link',
  'Advisories: deps.dev (this version)', 'Advisories: Snyk (this version)', 'Advisories: GitHub (all versions)'];
export const CATALOG_HEADER = ['Component', 'Type', 'Version', 'Identified from', 'Path found', 'Needs action'];

const FOUND_AS = { 'Electron runtime': "App's Electron version", lockfile: 'Lockfile', node_modules: 'Installed package (node_modules)', 'bundled library': 'Library file in the app' };
const paths = (row) => (row.locations && row.locations.length ? row.locations : row.files || []).join('\n');

/** Both sheets' rows. Cells are values, or { value, style } and { value, url } objects. */
export function componentTable(dependencies) {
  const all = (dependencies && dependencies.rows) || [];
  const actions = all.filter(needsAction).map(row => {
    const advisories = row.advisories || [];
    const highest = Math.max(0, ...advisories.map(a => RANK[a.severity] || 0));
    const labels = statusLabels(row);
    const links = componentLinks(row);
    return {
      // most urgent first: malicious, exploited in the wild, highest advisory severity, number of advisories, end of life or unsupported, majors behind
      sort: [row.malicious ? 1 : 0, advisories.some(a => a.kev) ? 1 : 0, highest, advisories.length,
        labels.includes('End of life') || labels.includes('Unsupported') ? 1 : 0, row.majorsBehind || 0],
      cells: [row.name, typeOf(row), row.version, date(row.released), row.latest || '', date(row.latestReleased), labels.join(', '), action(row, labels), paths(row),
        ...links.map(link)],
    };
  }).sort((a, b) => { for (let i = 0; i < a.sort.length; i++) if (a.sort[i] !== b.sort[i]) return b.sort[i] - a.sort[i]; return 0; });
  const catalog = [...all].sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version), undefined, { numeric: true }))
    .map(row => [row.name, typeOf(row), row.version, (row.kinds || []).map(kind => FOUND_AS[kind] || kind).join(', ') + (row.dev && !isElectron(row) ? ' (development only)' : ''),
      paths(row), needsAction(row) ? 'Yes' : 'No']);
  return { header: ACTION_HEADER, rows: actions.map(r => r.cells), catalogHeader: CATALOG_HEADER, catalog };
}

const column = (index) => { let s = ''; for (let n = index + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s; return s; };

// styles (cellXfs): 0 default, 1 header, 2 wrapped text, 3 link, 4 date
const HEADER = 1, TEXT = 2, LINK = 3, DATE = 4;

function cell(value, ref, style) {
  if (typeof value === 'number') return `<c r="${ref}" s="${style}"><v>${value}</v></c>`;
  return `<c r="${ref}" t="inlineStr" s="${style}"><is><t xml:space="preserve">${xmlText(String(value).slice(0, 32000))}</t></is></c>`;
}

/** A worksheet and the external links its cells carry. */
function worksheet(header, rows, widths) {
  const links = [];
  const body = rows.map((cells, r) => `<row r="${r + 2}">${cells.map((content, i) => {
    const ref = `${column(i)}${r + 2}`;
    if (content && typeof content === 'object') {
      if (content.url) {
        links.push({ ref, id: `rId${links.length + 1}`, url: content.url });
        return cell(content.value, ref, LINK);
      }
      return cell(content.value, ref, content.style || TEXT);
    }
    return cell(content ?? '', ref, TEXT);
  }).join('')}</row>`);
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<cols>${widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('')}</cols>
<sheetData><row r="1">${header.map((h, i) => cell(h, `${column(i)}1`, HEADER)).join('')}</row>${body.join('')}</sheetData>
<autoFilter ref="A1:${column(header.length - 1)}${rows.length + 1}"/>
${links.length ? `<hyperlinks>${links.map(l => `<hyperlink ref="${l.ref}" r:id="${l.id}"/>`).join('')}</hyperlinks>` : ''}
</worksheet>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${links.map(l => `<Relationship Id="${l.id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${xmlText(l.url)}" TargetMode="External"/>`).join('')}</Relationships>`;
  return { xml, rels };
}

const ACTION_SHEET = 'Components needing action';
const CATALOG_SHEET = 'All components';

/** The workbook as a Buffer. */
export function renderComponentsXlsx(dependencies, { appName } = {}) {
  const { header, rows, catalogHeader, catalog } = componentTable(dependencies);
  const actions = worksheet(header, rows, [26, 16, 14, 14, 14, 14, 30, 50, 50, 30, 30, 30, 30, 36]);
  const inventory = worksheet(catalogHeader, catalog, [30, 16, 14, 34, 70, 12]);
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd"/></numFmts>
<fonts count="3"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><sz val="10"/><color rgb="FF0563C1"/><u/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment horizontal="left" vertical="top"/></xf></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>`;
  const title = xmlText(`Components${appName ? ` - ${appName}` : ''}`);
  const filter = (sheet, index, columns, count) => `<definedName name="_xlnm._FilterDatabase" localSheetId="${index}" hidden="1">'${sheet}'!$A$1:$${column(columns - 1)}$${count + 1}</definedName>`;
  return zipFiles([
    ['[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`],
    ['_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`],
    ['docProps/core.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${title}</dc:title><dc:creator>Electronegativity</dc:creator></cp:coreProperties>`],
    ['xl/workbook.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${ACTION_SHEET}" sheetId="1" r:id="rId1"/><sheet name="${CATALOG_SHEET}" sheetId="2" r:id="rId2"/></sheets><definedNames>${filter(ACTION_SHEET, 0, header.length, rows.length)}${filter(CATALOG_SHEET, 1, catalogHeader.length, catalog.length)}</definedNames></workbook>`],
    ['xl/_rels/workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`],
    ['xl/worksheets/sheet1.xml', actions.xml],
    ['xl/worksheets/_rels/sheet1.xml.rels', actions.rels],
    ['xl/worksheets/sheet2.xml', inventory.xml],
    ['xl/styles.xml', styles],
  ]);
}
