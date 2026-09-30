import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const repo = path.resolve(import.meta.dirname, '..');
const modes = ['default', 'all-files'];
const finding = (id, file, line, severity = 'HIGH') => ({ id, file, line, severity });

function evaluate(style, falsePositive) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-benchmark-paths-'));
  const sources = path.join(root, 'sources'), output = path.join(root, 'results');
  fs.mkdirSync(output, { recursive: true });
  try {
    const cases = {
      'jitsi-vulnerable': [finding('OPEN_EXTERNAL_JS_CHECK', 'main.js', 165)],
      'jitsi-fixed': [finding('OPEN_EXTERNAL_JS_CHECK', 'app/features/utils/openExternalLink.js', 23, 'LOW')],
      'element-vulnerable': [finding('UNTRUSTED_LOAD_URL_JS_CHECK', 'src/protocol.ts', 32)],
      'element-fixed': [],
      'marktext-vulnerable': [finding('XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/renderBlock/renderLeafBlock.js', 251)],
      'marktext-fixed': [],
      'electerm-vulnerable': [finding('DYNAMIC_MODULE_JS_CHECK', 'src/app/widgets/load-widget.js', 68)],
      'electerm-fixed': [],
    };
    if (falsePositive) cases[falsePositive.app].push(falsePositive.issue);
    for (const [name, issues] of Object.entries(cases)) for (const mode of modes) {
      const report = { errors: [], issues: issues.map(issue => ({ ...issue,
        file: style === 'windows' ? issue.file.replaceAll('/', '\\') :
          style === 'mixed' ? issue.file.replace(/\//g, (separator, offset) => offset % 2 ? '\\' : separator) : issue.file,
      })) };
      fs.writeFileSync(path.join(output, `${name}-${mode}.json`), JSON.stringify(report));
    }

    // Minimal adapters let the CLI finish semantic controls; these tests target report matching.
    const adapters = {
      'electerm-vulnerable/src/app/widgets/load-widget.js': `const path = require('path');
module.exports.runWidget = id => require(path.join(__dirname, 'widget-' + id + '.js')).widgetRun();
`,
      'electerm-fixed/src/app/widgets/load-widget.js': `const path = require('path');
module.exports.runWidget = id => {
  if (!/^[a-z0-9-]+$/.test(id)) throw new Error('Invalid widget ID');
  return require(path.join(__dirname, 'widget-' + id + '.js')).widgetRun();
};
`,
      'marktext-fixed/src/main/utils/createGitHubIssue.js': `import { shell } from 'electron';
import { GITHUB_REPO_URL } from '../config';
export const createAndOpenGitHubIssueUrl = (title, body) => {
  const url = new URL(GITHUB_REPO_URL + '/issues/new');
  url.searchParams.set('title', title);
  url.searchParams.set('body', body);
  shell.openExternal(url.toString());
};
`,
    };
    for (const [relative, code] of Object.entries(adapters)) {
      const file = path.join(sources, relative);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, style === 'posix' ? code : code.replaceAll('\n', '\r\n'));
    }
    const result = spawnSync(process.execPath, ['scripts/evaluate-known-vulnerabilities.mjs', sources, output, '--ci'], {
      cwd: repo, encoding: 'utf8', timeout: 60000,
    });
    assert.ifError(result.error);
    assert.ok(fs.existsSync(path.join(output, 'evaluation.json')), result.stderr);
    return { status: result.status, summary: JSON.parse(fs.readFileSync(path.join(output, 'evaluation.json'), 'utf8')) };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

describe('Benchmark report paths', function () {
  this.timeout(120000);
  for (const style of ['posix', 'windows', 'mixed']) it(`passes all comparisons with ${style} paths`, () => {
    const { status, summary } = evaluate(style);
    assert.equal(status, 0, JSON.stringify(summary.gate));
    assert.deepEqual(summary.gate.failures, []);
    assert.equal(summary.pairs.length, 8);
    assert.equal(summary.controls.length, 11);
    assert.equal(summary.semanticEvidence.length, 33);
    assert.ok(summary.controls.every(control => control.result === 'pass'));
  });
  for (const [app, id, file, line, kind] of [
    ['electerm-fixed', 'HARDCODED_SECRET', 'src/client/components/tabs/quick-connect.jsx', 77, 'Credentials are UI examples'],
    ['electerm-fixed', 'HARDCODED_SECRET', 'src/client/components/setting-panel/setting-common.jsx', 325, 'Credentials are UI examples'],
    ['electerm-fixed', 'DEVELOPMENT_CODE_JS_CHECK', 'build/vite/conf.js', 1, 'Source build tooling described as shipped runtime code'],
    ['electerm-fixed', 'DEVELOPMENT_CODE_JS_CHECK', 'build/vite/dev-server.js', 1, 'Source build tooling described as shipped runtime code'],
    ['marktext-fixed', 'OPEN_EXTERNAL_JS_CHECK', 'src/main/utils/createGitHubIssue.js', 16, 'Fixed GitHub origin with encoded query parameters rated HIGH'],
  ]) it(`rejects a Windows false positive at ${file}`, () => {
    const { status, summary } = evaluate('windows', { app, issue: finding(id, file, line) });
    assert.equal(status, 1);
    const reviews = summary.falsePositives.filter(review => review.kind === kind);
    assert.equal(reviews.length, 2);
    assert.ok(reviews.every(review => review.findings.length === 1));
    assert.equal(summary.gate.failures.length, 2);
  });
});
