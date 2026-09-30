// The native Element CVE is an explicit coverage limit, never a blanket exemption for a failed scan.
export const CONTROL_NAMES = ['raw-html', 'noop-sanitize', 'unescaped-name', 'dompurify-control', 'raw-openexternal',
  'unrelated-validation', 'require-alias', 'create-require', 'overridden-sanitizer', 'noop-url-validator', 'rejected-url-branch'];

export function benchmarkFailures(summary, { fullCoverage = false } = {}) {
  const failures = [];
  for (const app of ['Jitsi', 'Element', 'MarkText', 'Electerm']) for (const mode of ['default', 'all-files']) {
    const matches = (summary.pairs || []).filter(p => p.app === app && p.mode === mode);
    if (matches.length !== 1) { failures.push(`${app}/${mode}: missing or duplicate comparison`); continue; }
    const allowedPartial = !fullCoverage && app === 'Element' && matches[0].result === 'partial';
    if (matches[0].result !== 'pass' && !allowedPartial) failures.push(`${app}/${mode}: ${matches[0].result}`);
  }
  for (const name of CONTROL_NAMES) {
    const matches = (summary.controls || []).filter(c => c.name === name);
    if (matches.length !== 1 || matches[0].result !== 'pass') failures.push(`control ${name}: missing, duplicate or failed`);
  }
  const reviews = [['Electerm', 'Credentials are UI examples'], ['Electerm', 'Source build tooling described as shipped runtime code'],
    ['MarkText', 'Fixed GitHub origin with encoded query parameters rated HIGH']];
  for (const [app, kind] of reviews) for (const mode of ['default', 'all-files'])
    if ((summary.falsePositives || []).filter(p => p.app === app && p.kind === kind && p.mode === mode).length !== 1)
      failures.push(`${app}/${mode}: missing or duplicate ${kind} review`);
  for (const review of summary.falsePositives || []) if (!Array.isArray(review.findings) || review.findings.length)
    failures.push(`${review.app}/${review.mode}: ${review.kind}`);
  return failures;
}
