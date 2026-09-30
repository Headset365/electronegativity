import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createAssistant } from '../src/watch/assistant.js';
import { capturedCampaign, normalizeCampaign } from '../src/watch/campaign.js';
const { inspectBody } = createRequire(import.meta.url)('../src/watch/capture.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const record = overrides => ({ kind: 'api', method: 'PUT', url: 'https://app.test/notes/42?token=private', status: 200,
  replay: 7, bodyFormat: 'json', fields: inspectBody('{"id":"42","password":"secret","body":"Hello","title":"Note"}').fields, ...overrides });

describe('Automatic capture campaigns', () => {
  it('proposes only captured content fields, without body values or authentication', () => {
    const profile = capturedCampaign(record());
    assert.deepEqual(profile.fields, ['body', 'title']);
    assert.equal(profile.cases.length, 28);
    assert.equal(profile.view, 'captured');
    assert.equal(profile.closeOnDone, false);
    assert.ok(!JSON.stringify(profile).includes('private'));
    assert.ok(!JSON.stringify(profile).includes('secret'));
    assert.ok(!JSON.stringify(profile).includes('Hello'));
    assert.throws(() => capturedCampaign(record(), { fields: ['password'] }));
    assert.throws(() => capturedCampaign(record(), { fields: ['missing'] }));
  });
  it('offers only form-compatible cases for a captured form', () => {
    const profile = capturedCampaign(record({ bodyFormat: 'form', fields: inspectBody('body=hello&id=42&token=secret').fields }));
    assert.deepEqual(profile.fields, ['body']);
    assert.equal(profile.cases.length, 23);
    assert.ok(!profile.cases.includes('null'));
  });
  it('rejects failed, redirected, incomplete and unsupported captures', () => {
    for (const overrides of [{ status: 403 }, { status: 302 }, { status: 0 }, { status: undefined }, { replay: undefined },
      { bodyFormat: undefined }, { fields: [{ name: 'token', candidate: false }] }]) assert.throws(() => capturedCampaign(record(overrides)));
    assert.throws(() => normalizeCampaign({ version: 1, request: { method: 'PUT', url: 'https://app.test/save', body: '{"body":"a"}' }, field: 'body', view: 'captured' }));
  });
  it('captures plain text, asks for fields and a view, then runs only after approval', async () => {
    const commands = [], saved = [], questions = [];
    const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, scope: ['app.test'], print: () => {}, saveCampaign: profile => saved.push(profile) });
    assistant.useChannel({ ask: async question => { questions.push(question); return ''; }, confirm: async question => { questions.push(question); return true; }, send: command => commands.push(command) });
    assistant.handle(record()); await tick();
    assert.equal(questions.length, 3);
    assert.equal(commands.length, 1);
    assert.equal(commands[0].kind, 'run-campaign');
    assert.equal(commands[0].replay, 7);
    assert.equal(commands[0].profile.view, 'captured');
    assert.equal(saved.length, 1);
    assert.equal(saved[0].capture.route, 'https://app.test/notes/{id}');
  });
  it('sends nothing when declined, cancelled or noninteractive', async () => {
    for (const mode of ['declined', 'cancelled', 'noninteractive']) {
      const commands = [];
      const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, print: () => {} });
      assistant.useChannel({ ask: mode === 'noninteractive' ? undefined : async () => mode === 'cancelled' ? undefined : '', confirm: async () => false, send: command => commands.push(command) });
      assistant.handle(record()); await tick(); assert.equal(commands.length, 0);
    }
  });
  it('checks scope and rejects an unsafe field selection before any test sends', async () => {
    for (const mode of ['scope', 'field']) {
      const commands = [], questions = [];
      const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, scope: mode === 'scope' ? ['other.test'] : [], print: () => {} });
      assistant.useChannel({ ask: async q => { questions.push(q); return 'password'; }, confirm: async () => true, send: c => commands.push(c) });
      assistant.handle(record()); await tick(); assert.equal(commands.length, 0);
      if (mode === 'scope') assert.equal(questions.length, 0);
    }
  });
  it('does not send an approved command after its session has closed', async () => {
    const commands = []; let approve;
    const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, print: () => {} });
    assistant.useChannel({ ask: async () => '', confirm: () => new Promise(resolve => { approve = resolve; }), send: c => commands.push(c) });
    assistant.handle(record()); await tick(); assistant.clearChannel(); approve(true); await tick();
    assert.equal(commands.length, 0);
  });
  it('serializes campaigns and ignores their own traffic until completion', async () => {
    const commands = [];
    const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, print: () => {} });
    assistant.useChannel({ ask: async () => '', confirm: async () => true, send: c => commands.push(c) });
    assistant.handle(record()); assistant.handle(record({ url: 'https://app.test/comments/2', replay: 8 })); await tick();
    assert.equal(commands.length, 1);
    assistant.handle(record({ url: 'https://app.test/campaign/2', replay: 9 })); await tick(); assert.equal(commands.length, 1);
    assistant.handle({ kind: 'campaign-done', cases: 28 }); await tick(); assert.equal(commands.length, 2);
    assistant.handle({ kind: 'campaign-done', cases: 28 }); await tick(); assert.equal(commands.length, 2);
  });
  it('keeps private view query strings out of saved profiles', async () => {
    const commands = [], saved = []; let count = 0;
    const assistant = createAssistant({ marker: 'ENG_AUTO_TEST', autoCampaign: true, print: () => {}, saveCampaign: p => saved.push(p) });
    assistant.useChannel({ ask: async () => count++ ? 'https://app.test/view?token=SECRET#secret' : 'body', confirm: async () => true, send: c => commands.push(c) });
    assistant.handle(record()); await tick();
    assert.equal(commands[0].profile.view, 'https://app.test/view?token=SECRET#secret');
    assert.equal(saved[0].view, 'https://app.test/view');
  });
});
