import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import http from 'node:http';
import { createRequire } from 'node:module';
import { once } from 'node:events';
import { load as loadHtml } from 'cheerio';
import { should as chaiShould } from 'chai';
import { normalizeCampaign, campaignMatch, hostsOutsideScope } from '../src/watch/campaign.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';

chaiShould();
const require = createRequire(import.meta.url);
const { valueFor, discoverFields, runCampaign, startResourceReceiver, CASES } = require('../src/watch/campaign.cjs');
const { DOCX_CASES, fixture: docxFixture, runDocxCampaign } = require('../src/watch/docx.cjs');
const { fillMarkerBody } = require('../src/watch/hook.cjs');
const { replayHeaders } = require('../src/watch/replay_headers.cjs');
const marker = 'ENGCAMPAIGN42';

describe('Profile-driven benign campaign', () => {
  it('replays header authentication without renderer Fetch Metadata or hop-by-hop headers', () => {
    replayHeaders({ Authorization: 'Bearer generated-test-token', 'X-CSRF-Token': 'generated-test-csrf',
      Origin: 'http://127.0.0.1:12345', Referer: 'http://127.0.0.1:12345/app/',
      'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'sec-ch-ua': 'test browser',
      Cookie: 'generated-test-cookie', 'Content-Length': '123', 'Transfer-Encoding': 'chunked',
      'Proxy-Authorization': 'generated-proxy-token' }).should.deep.equal({
      Authorization: 'Bearer generated-test-token', 'X-CSRF-Token': 'generated-test-csrf',
      Origin: 'http://127.0.0.1:12345', Referer: 'http://127.0.0.1:12345/app/' });
  });
  const direct = overrides => normalizeCampaign({ version: 1, request: { method: 'POST', url: 'http://127.0.0.1:9000/save',
    body: '{"id":1234567890123456789,"body":"original","title":"keep"}' }, field: 'body', view: 'reload', cases: ['event-handler', 'null'], ...overrides });

  it('requires an explicit route, field and view, and matches capture routes exactly', () => {
    direct().route.should.equal('POST http://127.0.0.1:9000/save');
    (() => direct({ field: 'id;rm' })).should.throw(/exact fields/);
    (() => direct({ cases: ['event-handler', 'event-handler'] })).should.throw(/unique/);
    (() => direct({ view: undefined })).should.throw(/view URL/);
    (() => direct({ request: { method: 'GET', url: 'https://example.test/x', body: '{}' } })).should.throw(/POST\/PUT\/PATCH/);
    const capture = normalizeCampaign({ version: 1, capture: { method: 'PUT', route: 'https://app.test/notes/{id}' }, field: 'body', view: 'reload', cases: ['text'] });
    campaignMatch(capture, { method: 'PUT', url: 'https://app.test/notes/42', replay: 1, fields: [{ name: 'body', html: false }] }).should.equal(true);
    campaignMatch(capture, { method: 'PUT', url: 'https://other.test/notes/42', replay: 1, fields: [{ name: 'body', html: true }] }).should.equal(false);
    campaignMatch(capture, { method: 'PUT', url: 'https://app.test/notes/42', replay: 1, status: 403, fields: [{ name: 'body', html: false }] }).should.equal(false);
    (() => direct({ cases: ['api-normal'] })).should.throw(/API cases require/);
    (() => direct({ cases: ['nav-loopback'] })).should.throw(/explicit view URL/);
    (() => direct({ field: undefined, fields: ['body', 'title'] })).should.not.throw();
    (() => direct({ field: undefined, fields: [] })).should.throw(/1–8 exact fields/);
  });

  it('names the hosts a campaign would write to outside --scope', () => {
    const capture = normalizeCampaign({ version: 1, capture: { method: 'PUT', route: 'https://api.app.test/notes/{id}' }, field: 'body', view: 'reload', cases: ['text'] });
    hostsOutsideScope(capture, []).should.deep.equal([]);
    hostsOutsideScope(capture, ['app.test']).should.deep.equal([]);
    hostsOutsideScope(capture, ['other.test']).should.deep.equal(['api.app.test']);
    hostsOutsideScope(direct(), ['app.test']).should.deep.equal(['127.0.0.1']);
  });

  it('discovers bounded document fields and keeps signals separate for each field', async () => {
    discoverFields('{"id":"123","token":"secret","body":"old","meta":{"title":"keep"},"items":[{"text":"one"}]}')
      .should.deep.equal(['body', 'meta.title', 'items[].text']);
    const profile = direct({ field: undefined, fields: ['body', 'title'], cases: ['event-handler', 'text'], restoreOnDone: false });
    const events = [];
    const bodies = [];
    await runCampaign({ profile, marker, fetch: async (_url, options) => { bodies.push(JSON.parse(options.body)); return { ok: true, status: 200 }; },
      fill: fillMarkerBody, view: async () => true, write: (kind, data) => events.push({ kind, ...data }), delay: async () => {} });
    bodies.should.have.length(4);
    bodies[0].title.should.equal('keep');
    bodies[2].body.should.equal('original');
    bodies[0].body.should.include(`ENG_CAMPAIGN:${marker}:event-handler:0:executed`);
    bodies[2].title.should.include(`ENG_CAMPAIGN:${marker}:event-handler:1:executed`);
    const observed = analyzeWatchLog([...events,
      { kind: 'campaign-result', case: 'event-handler', slot: 1, signal: 'executed', url: 'https://app.test/view' }]);
    observed.issues.filter(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT').should.have.length(1);
    observed.summary.campaign.cases.find(c => c.case === 'event-handler' && c.slot === 0).execution.should.equal('not observed');
    observed.summary.campaign.cases.find(c => c.case === 'event-handler' && c.slot === 1).execution.should.equal('observed');
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
    const send = events.find(e => e.kind === 'campaign-send');
    send.should.include({ ok: false });
    send.error.should.match(/requires a JSON/);
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

  it('requires a separately seeded, matching renderer data canary before reporting a read', async () => {
    const data = { name: 'eng_campaign_TEST42_cookie', value: '0123456789abcdef0123456789abcdef' };
    const signals = [];
    const scope = { console: { log: msg => signals.push(msg) }, document: { cookie: `${data.name}=${data.value}` },
      localStorage: { getItem: key => key === data.name ? data.value : null },
      indexedDB: { open: () => {
        const req = {};
        setImmediate(() => { req.result = { transaction: () => ({ objectStore: () => ({ get: () => {
          const get = {};
          setImmediate(() => { get.result = data.value; get.onsuccess(); });
          return get;
        } }) }), close: () => {} }; req.onsuccess(); });
        return req;
      } } };
    for (const name of ['cookie-canary', 'localstorage-canary', 'indexeddb-canary'])
      vm.runInNewContext(loadHtml(valueFor(name, marker, { data }))('img').attr('onerror'), scope);
    await new Promise(resolve => setImmediate(() => setImmediate(resolve)));
    signals.should.include(`ENG_CAMPAIGN:${marker}:cookie-canary:cookie-canary-read`);
    signals.should.include(`ENG_CAMPAIGN:${marker}:localstorage-canary:localstorage-canary-read`);
    signals.should.include(`ENG_CAMPAIGN:${marker}:indexeddb-canary:indexeddb-canary-read`);
    (() => valueFor('cookie-canary', marker)).should.throw(/canary is required/);
    const quiet = analyzeWatchLog([{ kind: 'campaign-send', case: 'cookie-canary', ok: true, status: 200 }]);
    quiet.issues.some(i => i.id === 'RUNTIME_CAMPAIGN_DATA_CANARY').should.equal(false);
    const proven = analyzeWatchLog([{ kind: 'campaign-send', case: 'cookie-canary', ok: true, status: 200 },
      { kind: 'campaign-result', case: 'cookie-canary', signal: 'cookie-canary-read', url: 'https://app.test/view' }]);
    proven.issues.some(i => i.id === 'RUNTIME_CAMPAIGN_DATA_CANARY').should.equal(true);
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
      const apiUrl = valueFor('api-loopback-url', marker, { resourceBase: url,
        api: { path: 'api.open', args: ['baseline'], mutationIndex: 0 }, slot: 1 });
      const called = [];
      const scope = { window: { api: { open: value => called.push(value) } }, console: { log: () => {} } };
      vm.runInNewContext(loadHtml(apiUrl)('img').attr('onerror'), scope);
      called.should.deep.equal([`${url}/api/${marker}/1`]);
      (await fetch(called[0])).status.should.equal(200);
      const effect = analyzeWatchLog([{ kind: 'campaign-send', case: 'api-loopback-url', slot: 1, route: 'POST https://app.test/save', status: 200, ok: true }, ...events]);
      effect.issues.some(i => i.id === 'RUNTIME_CAMPAIGN_API_EFFECT').should.equal(true);
      const nav = loadHtml(valueFor('nav-redirect', marker, { resourceBase: url, slot: 0 }))('a').attr('href');
      (await fetch(nav)).status.should.equal(200);
      events.slice(-2).map(e => e.case).should.deep.equal(['nav-redirect', 'nav-redirect']);
      const navigation = analyzeWatchLog([{ kind: 'campaign-send', case: 'nav-redirect', slot: 0, route: 'POST https://app.test/save', ok: true, status: 200 },
        { kind: 'campaign-action', case: 'nav-redirect', slot: 0, clicked: true, navigated: false, url: 'https://app.test/view' }, ...events]);
      navigation.issues.find(i => i.id === 'RUNTIME_CAMPAIGN_NAVIGATION').description.should.include('did not show a URL change');
    } finally { server.close(); await once(server, 'close'); }
  });

  it('imports bounded DOCX fixtures through a configured multipart endpoint without claiming conversion', async () => {
    const profile = normalizeCampaign({ version: 1, docxImport: { method: 'POST', url: 'http://127.0.0.1:9000/import', field: 'file',
      cases: ['baseline', 'metadata', 'malformed-xml'] }, view: 'reload' });
    profile.mode.should.equal('docx');
    (() => normalizeCampaign({ version: 1, docxImport: { method: 'POST', url: 'https://app.test/import', field: 'file',
      cases: ['zip-bomb'] }, view: 'reload' })).should.throw(/unique cases/);
    DOCX_CASES.should.include('external-relationship');
    const normal = docxFixture('baseline', marker);
    const malformed = docxFixture('malformed-xml', marker);
    normal.sha256.should.not.equal(malformed.sha256);
    normal.bytes.readUInt32LE(0).should.equal(0x04034b50);
    normal.bytes.length.should.be.below(100000);
    normal.bytes.toString('utf8').should.include('word/document.xml').and.include(marker);
    malformed.bytes.toString('utf8').should.include('</w:broken>');
    const receiverEvents = [];
    const receiver = await startResourceReceiver(marker, (kind, data) => receiverEvents.push({ kind, ...data }));
    const relation = docxFixture('external-relationship', marker, receiver.url);
    relation.bytes.toString('utf8').should.include(`${receiver.url}/docx/${marker}`);
    try {
      (await fetch(`${receiver.url}/docx/${marker}`)).status.should.equal(200);
      receiverEvents[0].kind.should.equal('docx-resource');
      const uploads = [];
      const events = [];
      await runDocxCampaign({ profile, marker, resourceBase: receiver.url,
        fetch: async (_url, options) => { uploads.push(options); return { ok: true, status: 201 }; },
        view: async () => true, write: (kind, data) => events.push({ kind, ...data }), delay: async () => {} });
      uploads.should.have.length(3);
      uploads[0].body.get('file').name.should.include('eng-baseline-');
      uploads[0].headers.should.deep.equal({});
      events.filter(e => e.kind === 'docx-send').should.have.length(3);
      const report = analyzeWatchLog(events);
      report.summary.docxCampaign.accepted.should.equal(3);
      report.issues.some(i => i.id === 'RUNTIME_DOCX_RESOURCE').should.equal(false);
      report.issues.find(i => i.id === 'RUNTIME_DOCX_IMPORT_CASE').description.should.include('does not prove conversion');
    } finally { receiver.server.close(); await once(receiver.server, 'close'); }
  });
});
