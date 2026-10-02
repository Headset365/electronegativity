// Captures the actual renderer on Windows CI, without launching an assessment or mocking a terminal screenshot.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { deflateSync } from 'node:zlib';
import { Dashboard } from '../src/tui/dashboard.js';

assert.equal(process.platform, 'win32', 'Generate TUI previews on Windows only.');
const root = 'tui-previews'; fs.mkdirSync(root, { recursive: true });
const ui = new Dashboard({ send: () => {}, close: () => {} });
ui.receive({ type: 'configuration', target: 'C:\\Users\\USER\\AppData\\Local\\Programs\\MyApp', autoCampaign: true });
ui.receive({ type: 'findings', counts: { high: 2, medium: 5, low: 3, info: 4 }, items: [] });
ui.receive({ type: 'session-start', number: 1 }); ui.receive({ type: 'session-live' });
ui.receive({ type: 'observer-ready', electron: '38' });
ui.receive({ type: 'campaign', key: 'PUT /api/notes/:id', status: 'completed', cases: 28, fields: ['body'], reason: '28 cases finished. Original fields restored.' });
ui.receive({ type: 'prompt', id: 8, kind: 'campaign', key: 'POST /api/comments', cases: 28, fields: ['content'] });
ui.receive({ type: 'campaign', key: 'PUT /api/profile', status: 'unavailable', reason: 'Save returned HTTP 403. No successful capture to replay.' });
ui.log('Validation', 'Observer connected. Use the app normally while runtime evidence is collected.');
ui.log('Validation', 'A content save was captured: POST /api/comments');
ui.log('Validation', '');
ui.log('Validation', 'NEXT STEP');
ui.log('Validation', 'Select Review & run beside the captured save. Choose its fields and saved-content view, then approve execution.');
ui.log('Validation', '');
ui.log('Validation', 'Completed · PUT /api/notes/:id');
ui.log('Validation', '28 cases delivered. Rendering and execution evidence is ready for review.');
ui.log('Validation', 'Original saved fields verified after restoration.');
ui.log('App output', '[stdout] MyApp ready');
ui.log('Tool logs', 'Static analysis complete. 14 findings written to the results folder.');
ui.log('Findings', 'HIGH  NODE_INTEGRATION_JS_CHECK | main.js:42 | Node integration enabled in a renderer.');
ui.log('Findings', 'MEDIUM  CSP_GLOBAL_CHECK | index.html:1 | Review the renderer content security policy.');
ui.notice = '1 campaign is ready. Review its fields and view before starting.';

const xml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
function capture(name, columns = 140, rows = 40) {
  ui.render(columns, rows);
  const { grid, width, height } = ui.surface, cellWidth = 10, cellHeight = 21;
  const svg = [`<svg xmlns="http://www.w3.org/2000/svg" width="${width * cellWidth}" height="${height * cellHeight}" viewBox="0 0 ${width * cellWidth} ${height * cellHeight}">`,
    '<style>text { font-family: "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace; font-size: 16px; }</style>'];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width;) {
      const start = x, color = grid[y][x].bg;
      while (x < width && grid[y][x].bg === color) x++;
      svg.push(`<rect x="${start * cellWidth}" y="${y * cellHeight}" width="${(x - start) * cellWidth}" height="${cellHeight}" fill="${color}"/>`);
    }
    for (let x = 0; x < width; x++) {
      const cell = grid[y][x];
      if (cell.char.trim()) svg.push(`<text x="${x * cellWidth}" y="${y * cellHeight + 16}" fill="${cell.fg}"${cell.bold ? ' font-weight="bold"' : ''}>${xml(cell.char)}</text>`);
    }
  }
  svg.push('</svg>'); fs.writeFileSync(`${root}/${name}.svg`, svg.join('\n'));
  // Compact, lossless cell data also allows review of the exact Windows-rendered screen from CI logs.
  console.log(`TUI_PREVIEW ${name} ${deflateSync(JSON.stringify({ width, height, grid })).toString('base64')}`);
}
capture('obsidian-live');
ui.themeIndex = 1; capture('midnight-live');
ui.themeIndex = 2; capture('porcelain-live');
ui.themeIndex = 0;
ui.receive({ type: 'prompt', id: 9, kind: 'text', question: '[validate] Fields to test, comma-separated [content]: ' });
ui.focus = 'input'; capture('content-fields');
ui.receive({ type: 'session-ended' });
ui.receive({ type: 'phase', text: 'Session 1 complete · evidence ready for review' });
ui.prompts = [{ id: 10, kind: 'session', question: 'Next session?' }]; ui.transition();
capture('session-review'); capture('compact-review', 80, 24);
