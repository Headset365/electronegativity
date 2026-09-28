import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import http from 'node:http';
import { createRequire } from 'node:module';
import { once } from 'node:events';
import { load as loadHtml } from 'cheerio';
import { should as chaiShould } from 'chai';
import { normalizeCampaign, campaignMatch } from '../src/watch/campaign.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';

chaiShould();
const require = createRequire(import.meta.url);
const { valueFor, runCampaign, startResourceReceiver, CASES } = require('../src/watch/campaign.cjs');
const { fillMarkerBody } = require('../src/watch/hook.cjs');
const marker = 'ENGCAMPAIGN42';

describe('Profile-driven benign campaign', () => {
  const direct = overrides => normalizeCampaign({ version: 1, request: { method: 'POST', url: 'http://127.0.0.1:9000/save',
    body: '{"id":1234567890123456789,"body":"original","title":"keep"}' }, field: 'body', view: 'reload', cases: ['event-handler', 'null'], ...overrides });

  it('requires an explicit route, field and view, and matches capture routes exactly', () => {
    direct().route.should.equal('POST http://127.0.0.1:9000/save');
    (() => direct({ field: 'id;rm' })).should.throw(/field name/);
    (() => direct({ cases: ['event-handler', 'event-handler'] })).should.throw(/unique/);
    (() => direct({ view: undefined })).should.throw(/view URL/);
    (() => direct({ request: { method: 'GET', url: 'https://example.test/x', body: '{}' } })).should.throw(/POST\/PUT\/PATCH/);
    const capture = normalizeCampaign({ version: 1, capture: { method: 'PUT', route: 'https://app.test/notes/{id}' }, field: 'body', view: 'reload', cases: ['text'] });
    campaignMatch(capture, { method: 'PUT', url: 'https://app.test/notes/42', replay: 1, fields: [{ name: 'body', html: false }] }).should.equal(true);
    campaignMatch(capture, { method: 'PUT', url: 'https://other.test/notes/42', replay: 1, fields: [{ name: 'body', html: true }] }).should.equal(false);
    campaignMatch(capture, { method: 'PUT', url: 'https://app.test/notes/42', replay: 1, status: 403, fields: [{ name: 'body', html: false }] }).should.equal(false);
    (() => direct({ cases: ['api-normal'] })).should.throw(/API cases require/);
  });

  it('delivers typed mutations through a real local endpoint without rewriting unrelated fields', async () => {
    const received = [];
    const server = http.createServer(async (req, res) => {
      let body = '';
      for await (const chunk of req) body += chunk;
      received.push({ body, headers: req.headers });
      res.writeHead(201); res.end('saved');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const profile = direct({ request: { method: 'POST', url: `http://127.0.0.1:${server.address().port}/save`,
        body: '{"id":1234567890123456789,"body":"original","title":"keep"}' },
      cases: ['event-handler', 'null', 'boolean', 'number', 'array', 'object', 'empty'] });
      const events = [];
      await runCampaign({ profile, marker, fetch, fill: fillMarkerBody, view: async () => true,
        write: (kind, data) => events.push({ kind, ...data }), delay: async () => {}, canary: () => { throw Error('not requested'); } });
      received.should.have.length(8);
      received.every(r => r.body.includes('1234567890123456789') && r.body.includes('"title":"keep"')).should.equal(true);
      received.map(r => JSON.parse(r.body).body).slice(1).should.deep.equal([null, false, 0, [marker], { probe: marker }, '', 'original']);
      received[0].body.should.include(`ENG_CAMPAIGN:${marker}:event-handler:executed`);
      events.filter(e => e.kind === 'campaign-send' && e.ok).should.have.length(7);
      events.find(e => e.kind === 'campaign-restore').ok.should.equal(true);
      const quiet = analyzeWatchLog(events).issues;
      quiet.some(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT').should.equal(false);
      quiet.filter(i => i.id === 'RUNTIME_CAMPAIGN_CASE').every(i => ['not observed', 'not applicable'].includes(i.properties.execution)).should.equal(true);
      const proven = analyzeWatchLog([...events, { kind: 'campaign-result', case: 'event-handler', signal: 'executed', url: 'https://app.test/view' }]).issues;
      proven.some(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT').should.equal(true);
    } finally { server.close(); await once(server, 'close'); }
  });

  it('creates distinct executable probes and proves the file canary only when its contents match', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-campaign-test-'));
    const canary = { path: path.join(dir, 'canary.txt'), value: 'random-canary-content-42' };
    fs.writeFileSync(canary.path, canary.value);
    try {
      const signals = [];
      const scope = { console: { log: msg => signals.push(msg) }, require, process: { versions: { electron: '38.0.0' } } };
      for (const name of ['event-handler', 'svg-handler', 'node', 'fs-read', 'eval']) {
        const $ = loadHtml(valueFor(name, marker, canary));
        const handler = $('img').attr('onerror') || $('svg').attr('onload');
        vm.runInNewContext(handler, scope, { timeout: 1000 });
        signals.should.include(`ENG_CAMPAIGN:${marker}:${name}:executed`);
      }
      signals.should.include(`ENG_CAMPAIGN:${marker}:fs-read:fs-read`);
      signals.should.include(`ENG_CAMPAIGN:${marker}:node:node-available`);
      signals.should.include(`ENG_CAMPAIGN:${marker}:eval:eval-allowed`);
      const script = loadHtml(valueFor('script-tag', marker))('script').html();
      vm.runInNewContext(script, scope, { timeout: 1000 });
      signals.should.include(`ENG_CAMPAIGN:${marker}:script-tag:executed`);
      CASES.should.include.members(['javascript-url', 'electron', 'long']);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('does not claim a typed form mutation or a completed campaign when delivery fails', async () => {
    const profile = direct({ request: { method: 'POST', url: 'https://app.test/save', body: 'body=old&title=keep' }, cases: ['null'] });
    const events = [];
    await runCampaign({ profile, marker, fetch: () => { throw Error('fetch should not run'); }, fill: fillMarkerBody, view: async () => true,
      write: (kind, data) => events.push({ kind, ...data }), delay: async () => {} });
    events[0].should.include({ kind: 'campaign-send', ok: false });
    events[0].error.should.match(/requires a JSON/);
    analyzeWatchLog(events).issues.some(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT').should.equal(false);
  });

  it('reports a failed restoration and an API call without inferring a privileged effect', () => {
    const issues = analyzeWatchLog([
      { kind: 'campaign-send', case: 'api-normal', route: 'POST https://app.test/save', ok: true, status: 200 },
      { kind: 'campaign-result', case: 'api-normal', signal: 'executed', url: 'https://app.test/view' },
      { kind: 'campaign-result', case: 'api-normal', signal: 'api-invoked', url: 'https://app.test/view' },
      { kind: 'campaign-result', case: 'api-normal', signal: 'api-resolved', url: 'https://app.test/view' },
      { kind: 'campaign-restore', ok: false, status: 409 },
    ]).issues;
    issues.find(i => i.id === 'RUNTIME_CAMPAIGN_API').description.should.match(/No IPC authorization or privileged effect/);
    issues.some(i => i.id === 'RUNTIME_CAMPAIGN_RESTORE').should.equal(true);
  });

  it('invokes only a declared page API with bounded argument mutations and no result contents in the signal', async () => {
    const received = [];
    const signals = [];
    const scope = { window: { api: { open(value) { received.push({ owner: this, value }); return { private: 'do-not-log' }; } } },
      console: { log: msg => signals.push(msg) } };
    const api = { path: 'api.open', args: ['baseline'], mutationIndex: 0 };
    for (const name of ['api-normal', 'api-null', 'api-traversal', 'api-absolute', 'api-file-url']) {
      const html = valueFor(name, marker, { api, path: '/tmp/controlled-canary.txt' });
      vm.runInNewContext(loadHtml(html)('img').attr('onerror'), scope, { timeout: 1000 });
    }
    await new Promise(resolve => setImmediate(resolve));
    received.map(r => r.value).should.deep.equal(['baseline', null, `../${marker}.txt`, '/tmp/controlled-canary.txt', 'file:///tmp/controlled-canary.txt']);
    received.every(r => r.owner === scope.window.api).should.equal(true);
    signals.should.include(`ENG_CAMPAIGN:${marker}:api-traversal:api-resolved`);
    JSON.stringify(signals).should.not.include('do-not-log');
  });

  it('serves controlled resources on loopback and records redirects without credential values', async () => {
    const events = [];
    const { server, url } = await startResourceReceiver(marker, (kind, data) => events.push({ kind, ...data }));
    try {
      const image = loadHtml(valueFor('external-image', marker, { resourceBase: url }))('img').attr('src');
      (await fetch(image, { headers: { Cookie: 'test-cookie', Authorization: 'Bearer test' } })).status.should.equal(200);
      events[0].should.include({ kind: 'campaign-resource', case: 'external-image', resource: 'image', cookiePresent: true, authorizationPresent: true });
      JSON.stringify(events).should.not.include('test-cookie').and.not.include('Bearer test');
      const redirect = loadHtml(valueFor('redirect-image', marker, { resourceBase: url }))('img').attr('src');
      (await fetch(redirect)).status.should.equal(200);
      events.slice(1).map(e => e.resource).should.deep.equal(['redirect', 'image']);
      events.slice(1).every(e => e.case === 'redirect-image').should.equal(true);
      (await fetch(`${url}/image/WRONGMARKER`)).status.should.equal(404);
      const found = analyzeWatchLog([{ kind: 'campaign-send', case: 'redirect-image', route: 'POST https://app.test/save', status: 200, ok: true }, ...events]).issues;
      found.filter(i => i.id === 'RUNTIME_CAMPAIGN_RESOURCE').should.have.length(2);
      found.some(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT').should.equal(false);
    } finally { server.close(); await once(server, 'close'); }
  });
});
