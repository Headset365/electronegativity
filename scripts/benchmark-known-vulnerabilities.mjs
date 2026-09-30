// Scan pinned upstream sources without installing or executing their code.
// Usage: node scripts/benchmark-known-vulnerabilities.mjs SOURCE_DIR OUTPUT_DIR
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sources = path.resolve(process.argv[2] || '../electron-benchmark/sources');
const output = path.resolve(process.argv[3] || '../electron-benchmark/results');
const cases = [
  ['jitsi-vulnerable', 'jitsi/jitsi-meet-electron', 'v2.0.0', '6ce4e51071b886ea804fa3ff182c3d89eca874f9'],
  ['jitsi-fixed', 'jitsi/jitsi-meet-electron', 'v2.3.0', '46bcc6fcf03fefc5b2ec3b546db592a070dd7374'],
  ['element-vulnerable', 'element-hq/element-desktop', 'v1.9.6', 'b79645adb47a0208ee438b49383b14b19bc7d421'],
  ['element-fixed', 'element-hq/element-desktop', 'v1.9.7', '6e28c141abfb688d8d5ec8dca8a5033098f6da76'],
  ['marktext-vulnerable', 'marktext/marktext', 'v0.16.3', 'cb38f99d2dbe8e828de390ad3a0c7263a59c3cb8'],
  ['marktext-fixed', 'marktext/marktext', 'v0.17.0', '637395a1f78278e375e0753c7b18e7833a6b9d58'],
  ['electerm-vulnerable', 'electerm/electerm', 'v3.7.9', '6256511ee210feda572f9e2ae281a1dcacac7db3'],
  ['electerm-fixed', 'electerm/electerm', 'v3.7.16', 'ff6621cc5394b46125e5fa453dc91e45addac692'],
];

fs.mkdirSync(output, { recursive: true });
fs.mkdirSync(sources, { recursive: true });
const scannerCommit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).stdout.trim();
const scannerWorktreeDirty = Boolean(spawnSync('git', ['status', '--porcelain'], { cwd: repo, encoding: 'utf8' }).stdout.trim());
const startedAt = new Date().toISOString();
const results = [];
let failed = false;
for (const [name, upstream, tag, expectedCommit] of cases) {
  const input = path.join(sources, name);
  if (!fs.existsSync(input) && process.argv.includes('--download')) {
    const clone = spawnSync('git', ['clone', '--depth', '1', '--branch', tag, `https://github.com/${upstream}.git`, input], { encoding: 'utf8', timeout: 180000 });
    if (clone.error || clone.status !== 0) throw new Error(`${name}: download failed: ${clone.error?.message || clone.stderr}`);
  }
  const actual = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: input, encoding: 'utf8' });
  const dirty = spawnSync('git', ['status', '--porcelain'], { cwd: input, encoding: 'utf8' });
  if (actual.status !== 0 || actual.stdout.trim() !== expectedCommit || dirty.status !== 0 || dirty.stdout.trim()) {
    throw new Error(`${name}: requires a clean checkout of ${expectedCommit}`);
  }
  for (const mode of ['default', 'all-files']) {
    const base = path.join(output, `${name}-${mode}`);
    // Remove stale report data so an unsuccessful scan cannot look successful.
    fs.rmSync(`${base}.json`, { force: true });
    const args = ['src/index.js', '-i', input, '--offline', '--no-report-dir', '-r', '-o', `${base}.json,${base}.html`, '--diagnostics', `${base}-diagnostics.json`];
    if (mode === 'all-files') args.push('--all-files');
    const start = performance.now();
    const scan = spawnSync(process.execPath, args, { cwd: repo, encoding: 'utf8', timeout: 180000, maxBuffer: 32 * 1024 * 1024 });
    fs.writeFileSync(`${base}.log`, `${scan.stdout || ''}\n${scan.stderr || ''}\n${scan.error || ''}`);
    let report;
    try { report = JSON.parse(fs.readFileSync(`${base}.json`, 'utf8')); } catch { /* recorded below */ }
    const row = { name, upstream, tag, commit: expectedCommit, mode, elapsedMs: Math.round(performance.now() - start), exitCode: scan.status, error: scan.error?.message, report: report ? `${base}.json` : null };
    failed ||= Boolean(scan.error) || scan.status !== 0 || !report;
    results.push(row);
    console.log(JSON.stringify(row));
    fs.writeFileSync(path.join(output, 'runs.json'), JSON.stringify({ scannerCommit, scannerWorktreeDirty, startedAt, node: process.version, offline: true, results }, null, 2));
  }
}
process.exitCode = failed ? 1 : 0;
