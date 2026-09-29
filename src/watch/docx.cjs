'use strict';
// Small, deterministic Office Open XML fixtures. No macros, formulas, scripts or unbounded compression.
const crypto = require('node:crypto');

const DOCX_CASES = ['baseline', 'metadata', 'external-relationship', 'svg-media', 'malformed-xml', 'duplicate-entry'];
const CONTENT_TYPES = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="svg" ContentType="image/svg+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>';
const ROOT_RELS = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
const esc = value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const crcTable = Array.from({ length: 256 }, (_, i) => { let c = i; for (let b = 0; b < 8; b++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
function crc32(bytes) { let c = 0xffffffff; for (const b of bytes) c = crcTable[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

function zip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const path = Buffer.from(name, 'utf8');
    const body = Buffer.from(content, 'utf8');
    if (!name || path.length > 200 || body.length > 100000) throw new Error('DOCX fixture exceeds its bounds');
    const crc = crc32(body);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt16LE(0x800, 6);
    head.writeUInt32LE(crc, 14); head.writeUInt32LE(body.length, 18); head.writeUInt32LE(body.length, 22); head.writeUInt16LE(path.length, 26);
    local.push(head, path, body);
    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0); dir.writeUInt16LE(20, 4); dir.writeUInt16LE(20, 6); dir.writeUInt16LE(0x800, 8);
    dir.writeUInt32LE(crc, 16); dir.writeUInt32LE(body.length, 20); dir.writeUInt32LE(body.length, 24);
    dir.writeUInt16LE(path.length, 28); dir.writeUInt32LE(offset, 42);
    central.push(dir, path);
    offset += head.length + path.length + body.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

function fixture(name, marker, resourceBase) {
  if (!DOCX_CASES.includes(name) || !/^[A-Za-z0-9_-]{8,80}$/.test(marker || '')) throw new Error('Unknown DOCX fixture');
  const paragraphs = name === 'metadata' ? 2 : 1;
  let text = Array.from({ length: paragraphs }, () => `<w:p><w:r><w:t>${esc(marker)}</w:t></w:r></w:p>`).join('');
  let relationships = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">';
  if (name === 'external-relationship') {
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(resourceBase || '')) throw new Error('Local DOCX receiver is required');
    relationships += `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${esc(`${resourceBase}/docx/${marker}`)}" TargetMode="External"/>`;
    text += `<w:p><w:hyperlink r:id="rId2"><w:r><w:t>${esc(marker)}</w:t></w:r></w:hyperlink></w:p>`;
  }
  if (name === 'svg-media') relationships += '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/probe.svg"/>';
  relationships += '</Relationships>';
  let document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${text}<w:sectPr/></w:body></w:document>`;
  if (name === 'malformed-xml') document = document.replace('</w:document>', '</w:broken>');
  const core = `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>${esc(marker)}</dc:title>${name === 'metadata' ? `<dc:description>${esc(marker)} metadata probe</dc:description>` : ''}</cp:coreProperties>`;
  const entries = [['[Content_Types].xml', CONTENT_TYPES], ['_rels/.rels', ROOT_RELS], ['word/document.xml', document],
    ['word/_rels/document.xml.rels', relationships], ['docProps/core.xml', core]];
  if (name === 'svg-media') entries.push(['word/media/probe.svg', `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><title>${esc(marker)}</title></svg>`]);
  if (name === 'duplicate-entry') entries.push(['word/document.xml', document.replaceAll(marker, `${marker}_duplicate`)]);
  const bytes = zip(entries);
  return { bytes, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
}

async function runDocxCampaign({ profile, marker, fetch, view, write, resourceBase, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const { docxImport, waitMs } = profile;
  for (const name of docxImport.cases) {
    try {
      const { bytes, sha256 } = fixture(name, marker, resourceBase);
      const form = new FormData();
      form.append(docxImport.field, new Blob([bytes], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }),
        `eng-${name}-${marker}.docx`);
      const response = await fetch(docxImport.url, { method: docxImport.method, headers: docxImport.headers, body: form });
      write('docx-send', { case: name, route: profile.docxRoute, ok: !!response.ok, status: response.status, sha256, bytes: bytes.length });
      if (response.ok && view) write('docx-view', { case: name, opened: !!await view(name) });
    } catch (error) {
      write('docx-send', { case: name, route: profile.docxRoute, ok: false, error: String(error && error.message || error).slice(0, 160) });
    }
    await delay(waitMs);
  }
  write('docx-done', { cases: docxImport.cases.length });
}

module.exports = { DOCX_CASES, fixture, runDocxCampaign };
