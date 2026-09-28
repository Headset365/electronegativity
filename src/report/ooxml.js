// A minimal WordprocessingML (.docx) writer with no dependencies: headings, paragraphs with bold / italic / monospace /
// coloured runs, hyperlinks and bookmarks, bullet lists, tables with a shaded header row, page breaks and a table of
// contents field Word fills in when the document opens. A port of Electron-Dynamic's report/ooxml.py.
import zlib from 'node:zlib';

const W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';

// text as XML: characters XML 1.0 forbids are dropped
export function xmlText(value) {
  // eslint-disable-next-line no-control-regex
  return String(value ?? '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]/g, '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export class Doc {
  constructor(title = 'Report') {
    this.title = title;
    this.body = [];
    this.links = [];
    this.bookmarks = 0;
  }

  run(text, { bold = false, italic = false, mono = false, color, size } = {}) {
    let props = '';
    if (mono) props += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>';
    if (bold) props += '<w:b/>';
    if (italic) props += '<w:i/>';
    if (color) props += `<w:color w:val="${color}"/>`;
    if (size) props += `<w:sz w:val="${Math.round(size * 2)}"/>`;
    const lines = String(text ?? '').split('\n').map((line, i) => `${i ? '<w:br/>' : ''}<w:t xml:space="preserve">${xmlText(line)}</w:t>`).join('');
    return `<w:r>${props ? `<w:rPr>${props}</w:rPr>` : ''}${lines}</w:r>`;
  }

  link(text, url) {
    if (!url) return this.run(text);
    this.links.push(String(url));
    return `<w:hyperlink r:id="rIdL${this.links.length}"><w:r><w:rPr><w:rStyle w:val="Hyperlink"/></w:rPr><w:t xml:space="preserve">${xmlText(text)}</w:t></w:r></w:hyperlink>`;
  }

  /** A link to a bookmark in this document. */
  anchorLink(text, anchor) {
    return `<w:hyperlink w:anchor="${xmlText(anchor)}"><w:r><w:rPr><w:rStyle w:val="Hyperlink"/></w:rPr><w:t xml:space="preserve">${xmlText(text)}</w:t></w:r></w:hyperlink>`;
  }

  bookmark(name, ...runs) {
    this.bookmarks++;
    return `<w:bookmarkStart w:id="${this.bookmarks}" w:name="${xmlText(name)}"/>${runs.map(r => this.asRun(r)).join('')}<w:bookmarkEnd w:id="${this.bookmarks}"/>`;
  }

  asRun(r) {
    return String(r).startsWith('<w:') ? r : this.run(r);
  }

  para(runs, { style, keepNext = false, spacingAfter } = {}) {
    let props = '';
    if (style) props += `<w:pStyle w:val="${style}"/>`;
    if (keepNext) props += '<w:keepNext/>';
    if (spacingAfter !== undefined) props += `<w:spacing w:after="${spacingAfter}"/>`;
    const list = Array.isArray(runs) ? runs : [runs];
    this.body.push(`<w:p>${props ? `<w:pPr>${props}</w:pPr>` : ''}${list.map(r => this.asRun(r)).join('')}</w:p>`);
  }

  heading(text, level = 1, bookmark) {
    const run = this.run(text);
    this.para(bookmark ? this.bookmark(bookmark, run) : run, { style: `Heading${level}`, keepNext: true });
  }

  bullet(runs) {
    this.para(runs, { style: 'ListBullet' });
  }

  label(text) {
    this.para(text, { style: 'Label' });
  }

  code(text) {
    for (const line of String(text ?? '').split('\n').slice(0, 40)) this.para(this.run(line), { style: 'Code' });
  }

  pageBreak() {
    this.body.push('<w:p><w:r><w:br w:type="page"/></w:r></w:p>');
  }

  /** A table of contents field; Word fills it when the document is opened (updateFields is set). */
  toc() {
    this.body.push('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>' +
      '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>Right-click and choose Update Field to build the table of contents.</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>');
  }

  /** headers: strings; rows: arrays of cells, each plain text or an array of run XML. widths: relative weights. */
  table(headers, rows, { widths, fontSize } = {}) {
    const textWidth = 11906 - 2 * 1134;
    const weights = widths || headers.map(() => 1);
    const total = weights.reduce((a, b) => a + b, 0);
    const cols = weights.map(w => Math.floor(textWidth * w / total));
    const cell = (content, width, header = false) => {
      const shade = header ? '<w:shd w:val="clear" w:color="auto" w:fill="1F3864"/>' : '';
      const runs = Array.isArray(content) ? content.join('') : this.run(content, { bold: header, color: header ? 'FFFFFF' : undefined, size: fontSize });
      return `<w:tc><w:tcPr><w:tcW w:w="${width}" w:type="dxa"/>${shade}</w:tcPr><w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>${runs}</w:p></w:tc>`;
    };
    const head = `<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>${headers.map((h, i) => cell(h, cols[i], true)).join('')}</w:tr>`;
    const body = rows.map(row => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${headers.map((_, i) => cell(row[i] ?? '', cols[i])).join('')}</w:tr>`).join('');
    this.body.push(`<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="${cols.reduce((a, b) => a + b, 0)}" w:type="dxa"/><w:tblLayout w:type="fixed"/></w:tblPr>` +
      `<w:tblGrid>${cols.map(w => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>${head}${body}</w:tbl>`);
    this.body.push('<w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>');
  }

  toBuffer() {
    const section = '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>';
    const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="${W}" xmlns:r="${R}"><w:body>${this.body.join('')}${section}</w:body></w:document>`;
    const links = this.links.map((url, i) => `<Relationship Id="rIdL${i + 1}" Type="${R}/hyperlink" Target="${xmlText(url)}" TargetMode="External"/>`).join('');
    const rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      `<Relationship Id="rIdStyles" Type="${R}/styles" Target="styles.xml"/><Relationship Id="rIdNum" Type="${R}/numbering" Target="numbering.xml"/>` +
      `<Relationship Id="rIdSettings" Type="${R}/settings" Target="settings.xml"/>${links}</Relationships>`;
    const core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ' +
      `xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${xmlText(this.title)}</dc:title><dc:creator>Electronegativity</dc:creator></cp:coreProperties>`;
    return zipFiles([['[Content_Types].xml', CONTENT_TYPES], ['_rels/.rels', ROOT_RELS], ['docProps/core.xml', core], ['word/document.xml', document],
      ['word/_rels/document.xml.rels', rels], ['word/styles.xml', STYLES], ['word/numbering.xml', NUMBERING], ['word/settings.xml', SETTINGS]]);
  }
}

/** A zip archive of [name, text or Buffer] entries, deflated. */
export function zipFiles(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const packed = zlib.deflateRawSync(data);
    const nameBytes = Buffer.from(name, 'utf8');
    const crc = zlib.crc32(data) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(0x21, 12); // 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    locals.push(local, nameBytes, packed);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(0x800, 8);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt16LE(0x21, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(packed.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}

const CONTENT_TYPES = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' +
  '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>' +
  '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>' +
  '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>' +
  '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>' +
  '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>';

const ROOT_RELS = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>' +
  '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>';

const SETTINGS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="${W}"><w:defaultTabStop w:val="720"/><w:updateFields w:val="true"/>` +
  '<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>';

const NUMBERING = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:numbering xmlns:w="${W}"><w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/>` +
  '<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="360" w:hanging="360"/></w:pPr></w:lvl>' +
  '</w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num></w:numbering>';

const headingStyle = (level, size, color, before) => `<w:style w:type="paragraph" w:styleId="Heading${level}"><w:name w:val="heading ${level}"/><w:basedOn w:val="Normal"/>` +
  `<w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="${before}" w:after="120"/><w:outlineLvl w:val="${level - 1}"/></w:pPr>` +
  `<w:rPr><w:b/><w:color w:val="${color}"/><w:sz w:val="${size}"/></w:rPr></w:style>`;

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="${W}">` +
  '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri" w:eastAsia="Calibri"/><w:sz w:val="20"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>' +
  '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>' +
  '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>' +
  '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="240"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3864"/><w:sz w:val="48"/></w:rPr></w:style>' +
  headingStyle(1, 32, '1F3864', 360) + headingStyle(2, 26, '2E74B5', 280) + headingStyle(3, 22, '1F3864', 200) +
  '<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr><w:spacing w:after="40"/></w:pPr></w:style>' +
  '<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/><w:spacing w:after="60" w:line="240" w:lineRule="auto"/><w:ind w:left="144"/></w:pPr>' +
  '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="16"/></w:rPr></w:style>' +
  '<w:style w:type="paragraph" w:styleId="Label"><w:name w:val="Label"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="40"/></w:pPr><w:rPr><w:b/><w:color w:val="2E74B5"/></w:rPr></w:style>' +
  '<w:style w:type="paragraph" w:styleId="TOCHeading"><w:name w:val="TOC Heading"/><w:basedOn w:val="Heading1"/><w:next w:val="Normal"/></w:style>' +
  '<w:style w:type="paragraph" w:styleId="TOC1"><w:name w:val="toc 1"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>' +
  '<w:style w:type="paragraph" w:styleId="TOC2"><w:name w:val="toc 2"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="40"/><w:ind w:left="220"/></w:pPr></w:style>' +
  '<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/><w:rPr><w:color w:val="0563C1"/><w:u w:val="single"/></w:rPr></w:style>' +
  '<w:style w:type="table" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:rPr><w:sz w:val="18"/></w:rPr><w:tblPr><w:tblBorders>' +
  ['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(side => `<w:${side} w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>`).join('') +
  '</w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>';
