// The outdated components spreadsheet (-o components.xlsx) that the client report's "Outdated Third-Party Components"
// finding refers to: one sheet, one row per component that is outdated, unsupported, end of life, deprecated or has
// published advisories, with what to upgrade to. Written as a plain SpreadsheetML workbook with the same zip writer as
// the Word report, no dependencies.
import { zipFiles, xmlText } from './ooxml.js';

const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, MODERATE: 2, LOW: 1 };

/** Components worth listing: behind the latest release, unsupported or end of life, deprecated, or with advisories. */
export function outdatedRows(dependencies) {
  const rows = (dependencies && dependencies.rows) || [];
  return rows.filter(r => (r.advisories || []).length > 0 || ['unsupported', 'outdated'].includes(r.support && r.support.status) || r.deprecated ||
    (r.latest && r.version && r.latest !== r.version && (r.versionsBehind === undefined || r.versionsBehind > 0)));
}

const typeOf = (row) => row.kinds.includes('Electron runtime') ? 'Electron runtime' : row.kinds.includes('bundled library') ? 'Bundled library copy' : 'npm package';

function action(row) {
  const status = row.support && row.support.status;
  if (row.malicious) return `Remove immediately: known malicious version (${row.malicious.id})`;
  if (row.deprecated && !row.latest) return 'Replace: deprecated and no longer maintained';
  const target = row.fixedIn || (status !== 'unsupported' && row.latestInMajor && row.latestInMajor !== row.version ? row.latestInMajor : row.latest);
  if (row.fixedIn === null) return `Upgrade to ${row.latest || 'a supported release'}; some advisories have no fixed version in this line`;
  if (status === 'unsupported') return `Upgrade to a supported release line${row.latest ? ` (latest ${row.latest})` : ''}`;
  return target ? `Upgrade to ${target}${row.latest && target !== row.latest ? ` or later (latest ${row.latest})` : ''}` : 'Review';
}

/** The table: header row and one row per component, most urgent first. */
export function componentTable(dependencies) {
  const header = ['Component', 'Type', 'Installed version', 'Latest version', 'Installed version released', 'Latest version released', 'Versions behind',
    'Major versions behind', 'Support status', 'Support detail', 'Advisories', 'Highest advisory severity', 'Advisory IDs', 'CVEs',
    'Exploited in the wild (CISA KEV)', 'Highest EPSS', 'Fixed in', 'Recommended action', 'Found in'];
  const rows = outdatedRows(dependencies).map(row => {
    const advisories = row.advisories || [];
    const highest = advisories.map(a => a.severity).filter(Boolean).sort((a, b) => (RANK[b] || 0) - (RANK[a] || 0))[0];
    const cves = [...new Set(advisories.flatMap(a => a.cves || []))];
    const epss = advisories.map(a => a.epss && a.epss.epss).filter(v => typeof v === 'number').sort((a, b) => b - a)[0];
    return {
      sort: [row.malicious ? 1 : 0, advisories.some(a => a.kev) ? 1 : 0, RANK[highest] || 0, advisories.length, row.support && row.support.status === 'unsupported' ? 1 : 0, row.majorsBehind || 0],
      cells: [row.name, typeOf(row), row.version, row.latest || '', row.released || '', row.latestReleased || '', row.versionsBehind ?? '', row.majorsBehind ?? '',
        (row.support && row.support.status) || 'unknown', (row.support && row.support.detail) || '', advisories.length, highest ? highest.replace('MODERATE', 'MEDIUM') : '',
        advisories.map(a => a.id).join(', '), cves.join(', '), advisories.some(a => a.kev) ? 'Yes' : 'No', epss !== undefined ? Number(epss.toFixed(4)) : '',
        row.fixedIn || '', action(row), (row.files || []).join(', ')],
    };
  }).sort((a, b) => { for (let i = 0; i < a.sort.length; i++) if (a.sort[i] !== b.sort[i]) return b.sort[i] - a.sort[i]; return 0; });
  return { header, rows: rows.map(r => r.cells) };
}

const column = (index) => { let s = ''; for (let n = index + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s; return s; };

function cell(value, ref, style) {
  if (typeof value === 'number') return `<c r="${ref}"${style ? ` s="${style}"` : ''}><v>${value}</v></c>`;
  return `<c r="${ref}" t="inlineStr"${style ? ` s="${style}"` : ''}><is><t xml:space="preserve">${xmlText(String(value).slice(0, 32000))}</t></is></c>`;
}

/** The workbook as a Buffer. */
export function renderComponentsXlsx(dependencies, { appName } = {}) {
  const { header, rows } = componentTable(dependencies);
  const widths = [28, 20, 14, 14, 14, 14, 10, 10, 14, 50, 10, 14, 40, 40, 14, 10, 14, 50, 50];
  const last = column(header.length - 1);
  const sheetRows = [
    `<row r="1">${header.map((h, i) => cell(h, `${column(i)}1`, 1)).join('')}</row>`,
    ...rows.map((cells, r) => `<row r="${r + 2}">${cells.map((v, i) => cell(v, `${column(i)}${r + 2}`, 2)).join('')}</row>`),
  ];
  const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<cols>${widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('')}</cols>
<sheetData>${sheetRows.join('')}</sheetData>
${rows.length ? `<autoFilter ref="A1:${last}${rows.length + 1}"/>` : ''}
</worksheet>`;
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf></cellXfs>
</styleSheet>`;
  const title = xmlText(`Outdated components${appName ? ` - ${appName}` : ''}`);
  return zipFiles([
    ['[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`],
    ['_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`],
    ['docProps/core.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${title}</dc:title><dc:creator>Electronegativity</dc:creator></cp:coreProperties>`],
    ['xl/workbook.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Outdated components" sheetId="1" r:id="rId1"/></sheets>${rows.length ? `<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'Outdated components'!$A$1:$${last}$${rows.length + 1}</definedName></definedNames>` : ''}</workbook>`],
    ['xl/_rels/workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`],
    ['xl/worksheets/sheet1.xml', sheet],
    ['xl/styles.xml', styles],
  ]);
}
