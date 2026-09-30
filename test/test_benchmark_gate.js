import assert from 'node:assert/strict';
import { benchmarkFailures, CONTROL_NAMES } from '../scripts/benchmark-policy.mjs';

function passing() {
  const modes = ['default', 'all-files'];
  return {
    pairs: ['Jitsi', 'Element', 'MarkText', 'Electerm'].flatMap(app => modes.map(mode => ({ app, mode, result: app === 'Element' ? 'partial' : 'pass' }))),
    controls: CONTROL_NAMES.map(name => ({ name, result: 'pass' })),
    falsePositives: [['Electerm', 'Credentials are UI examples'], ['Electerm', 'Source build tooling described as shipped runtime code'],
      ['MarkText', 'Fixed GitHub origin with encoded query parameters rated HIGH']].flatMap(([app, kind]) => modes.map(mode => ({ app, kind, mode, findings: [] }))),
  };
}

describe('Benchmark CI gate', () => {
  it('permits only the documented native-CVE coverage limit', () => assert.deepEqual(benchmarkFailures(passing()), []));
  it('keeps full coverage strict', () => assert.equal(benchmarkFailures(passing(), { fullCoverage: true }).length, 2));
  it('fails a source-pattern regression', () => { const s = passing(); s.pairs[0].result = 'gap'; assert.ok(benchmarkFailures(s).length); });
  it('does not exempt a missing Element mitigation', () => { const s = passing(); s.pairs.find(p => p.app === 'Element').result = 'gap'; assert.ok(benchmarkFailures(s).length); });
  it('fails missing and duplicate comparisons', () => {
    for (const mutate of [s => s.pairs.pop(), s => s.pairs.push(s.pairs[0])]) { const s = passing(); mutate(s); assert.ok(benchmarkFailures(s).length); }
  });
  it('fails missing, duplicate and failed controls', () => {
    for (const mutate of [s => s.controls.pop(), s => s.controls.push(s.controls[0]), s => { s.controls[0].result = 'gap'; }]) { const s = passing(); mutate(s); assert.ok(benchmarkFailures(s).length); }
  });
  it('fails reintroduced false positives and incomplete reviews', () => {
    for (const mutate of [s => s.falsePositives[0].findings.push({}), s => s.falsePositives.pop(), s => { s.falsePositives[0] = s.falsePositives[1]; }]) { const s = passing(); mutate(s); assert.ok(benchmarkFailures(s).length); }
  });
});
