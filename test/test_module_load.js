import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { analyzeWatchLog } from '../src/watch/analyze.js';

const { observeModuleLoads } = createRequire(import.meta.url)('../src/watch/module-load.cjs');
const marker = 'ENG_MODULE_TEST';

describe('Module load runtime evidence', () => {
  it('preserves loader arguments, receiver and exported identity', () => {
    const records = [], receiver = {}, parent = { filename: '/app/main.js' }, exported = {};
    const wrapped = observeModuleLoads(function (request, from, main) {
      assert.equal(this, receiver); assert.equal(from, parent); assert.equal(main, false); return exported;
    }, { marker, resolve: () => `/app/${marker}.js`, record: r => records.push(r) });
    assert.equal(wrapped.call(receiver, `./${marker}`, parent, false), exported);
    assert.equal(records.length, 1); assert.equal(records[0].resolved, `/app/${marker}.js`); assert.equal(records[0].ok, true);
  });
  it('preserves the actual exception and records a failed load', () => {
    const records = [], error = Object.assign(new Error('missing'), { code: 'MODULE_NOT_FOUND' });
    const wrapped = observeModuleLoads(() => { throw error; }, { marker, resolve: () => { throw error; }, record: r => records.push(r) });
    assert.throws(() => wrapped(marker, {}), e => e === error);
    assert.equal(records[0].ok, false); assert.equal(records[0].errorCode, 'MODULE_NOT_FOUND');
  });
  it('does not inspect or record ordinary module loads', () => {
    const forbidden = () => { throw new Error('observer must not run'); };
    const wrapped = observeModuleLoads(() => 42, { marker, resolve: forbidden, record: forbidden });
    assert.equal(wrapped('path', {}), 42);
  });
  it('requires a valid, explicit marker', () => {
    for (const token of ['', undefined, 'x', '../invalid-marker']) {
      let records = 0;
      assert.equal(observeModuleLoads(() => 42, { marker: token, resolve: () => { throw Error(); }, record: () => records++ })('ENG_MODULE_TEST', {}), 42);
      assert.equal(records, 0);
    }
  });
  it('never lets observer failures alter the app result', () => {
    assert.equal(observeModuleLoads(() => 42, { marker, resolve: () => { throw Error(); }, record: () => { throw Error(); } })(marker, {}), 42);
  });
  it('redacts credentials from observed module requests', () => {
    const records = [];
    const request = `https://user:RealSecret123@host/${marker}`;
    observeModuleLoads(() => 42, { marker, resolve: () => request, record: r => records.push(r) })(request, { filename: request });
    assert.ok(!records[0].request.includes('RealSecret123'));
    assert.ok(!records[0].resolved.includes('RealSecret123')); assert.ok(!records[0].parent.includes('RealSecret123'));
  });
  it('reports successful and failed loads without asserting traversal or policy enforcement', () => {
    const records = [{ kind: 'start' }, ...[true, false].map(ok => ({ kind: 'module-load', marker: true, request: marker, resolved: `/app/${marker}.js`, parent: '/app/main.js', ok }))];
    const findings = analyzeWatchLog(records).issues.filter(i => i.id === 'RUNTIME_MARKER_MODULE');
    assert.equal(findings.length, 2);
    assert.deepEqual(findings.map(i => i.properties.loaded), [true, false]);
    assert.match(findings[0].description, /exploitability remain unverified/);
    assert.match(findings[1].description, /does not establish.*security policy/);
  });
});
