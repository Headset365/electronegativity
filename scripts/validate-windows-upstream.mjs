// Disposable Windows-only upstream release validation. No login or exploit commands.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { execFileSync } from 'node:child_process';
import run from '../src/runner.js';
import i18n from '../src/locales/i18n.js';
import { observeSession } from '../src/watch/session.js';
import { readWatchLog, analyzeWatchLog } from '../src/watch/analyze.js';
import { readManifest } from '../src/watch/launch.js';
import { unpackTarget } from '../src/unpack/index.js';
import { parsePe } from '../src/binary/pe.js';

const config = JSON.parse(fs.readFileSync(new URL('./windows-upstream-apps.json', import.meta.url), 'utf8'));
const spec = config.apps.find(a => a.id === process.argv[2]);
if (!spec || process.platform !== 'win32') throw Error('A configured app and a native Windows runner are required');
const repo = path.resolve(import.meta.dirname, '..');
const out = path.join(repo, 'validation-results', spec.id);
const work = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'eng-upstream-' + spec.id);
fs.mkdirSync(out, { recursive: true }); fs.mkdirSync(work, { recursive: true });
const status = {
  app: spec.name, version: spec.version, advisory: spec.advisory,
  startedAt: new Date().toISOString(), scannerCommit: config.scannerCommit,
  harnessCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  runner: { platform: process.platform, release: os.release(), architecture: process.arch, node: process.version,
    image: process.env.ImageOS, imageVersion: process.env.ImageVersion },
  scope: 'Shipped x64 Windows package plus an automated fresh-profile startup watch session with bounded proofs',
  limits: [
    spec.advisory.limitation,
    'No app accounts, remote meeting/SSH server, signed-in state or logout workflow are configured.',
    'No reviewed app-specific IPC, link or local-service contract is supplied; those probes are skipped.',
    'The startup session is closed by terminating the observed main process after 45 seconds of hook observation (180-second outer limit).',
    'The package is extracted, not installed: ACLs describe this extraction folder; installer-created registry entries are not established.',
    'Hosted Windows Server is the actual test OS, not a Windows 10/11 desktop certification.',
    'Online dependency intelligence is enabled. Chromium NVD lookups and workbook URL link checks are disabled; lookup failures remain visible.',
    'A scanner finding is not proof that the selected advisory was exploited. Bundled/minified code and parser gaps can limit static detection.',
  ],
};
const persist = () => fs.writeFileSync(path.join(out, 'validation.json'), JSON.stringify(status, null, 2));
async function hash(file) {
  const digest = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) digest.update(chunk);
  return digest.digest('hex');
}
async function download(url, file) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(180000), headers: { 'User-Agent': 'electronegativity-validation' } });
      if (!res.ok || !res.body) throw Error('Download returned HTTP ' + res.status);
      await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(file));
      return;
    } catch (error) { fs.rmSync(file, { force: true }); if (attempt === 3) throw error; }
  }
}
let session, installer, scan;
try {
  await i18n();
  const packageFile = path.join(work, spec.asset);
  console.log('Downloading pinned ' + spec.name + ' ' + spec.version);
  await download(spec.url, packageFile);
  status.package = { url: spec.url, file: spec.asset, size: fs.statSync(packageFile).size, sha256: await hash(packageFile), expectedSha256: spec.sha256 || null };
  if (spec.sha256 && status.package.sha256 !== spec.sha256) throw Error('Upstream release SHA-256 mismatch');
  persist();
  console.log('Extracting shipped package');
  installer = unpackTarget(packageFile, { workDir: path.join(work, 'extracted') });
  if (!installer.code || !installer.mainExe) throw Error('Package did not resolve to a shipped Electron application');
  const manifest = readManifest(installer.code);
  if (String(manifest.version).replace(/^v/, '') !== spec.version) throw Error('Shipped manifest version mismatch: ' + manifest.version);
  const architecture = parsePe(fs.readFileSync(installer.mainExe), { resources: false }).machine;
  if (architecture !== 'x64') throw Error('Expected x64 Windows executable, found ' + architecture);
  status.shipped = { kind: installer.kind, manifestVersion: manifest.version, architecture,
    executable: path.basename(installer.mainExe), asarSha256Before: await hash(installer.code), executableSha256Before: await hash(installer.mainExe),
    warnings: installer.warnings };
  persist();
  console.log('Observing real packaged app startup with bounded handler/TLS/fuse proofs');
  let hooked = false, stopTimer, outerTimer;
  const stop = () => { console.log('Closing bounded startup watch'); process.emit('SIGINT'); };
  outerTimer = setTimeout(stop, 180000);
  try {
    session = await observeSession({ watch: installer.mainExe, prove: true, capture: false, traffic: true,
      assistant: {
        handle(record) {
          if (record.kind === 'start' && !hooked) { hooked = true; clearTimeout(outerTimer); stopTimer = setTimeout(stop, 45000); }
        },
        printSummary() {},
      },
    });
    fs.copyFileSync(session.watchLog, path.join(out, 'session.jsonl'));
    const rows = readWatchLog(session.watchLog);
    status.watch = { diagnostics: session.watchDiagnostics, records: rows.length,
      proofs: rows.filter(r => r.kind === 'proof'),
      windows: rows.filter(r => r.kind === 'window'),
      inventory: rows.filter(r => /^(windows-|motw)/.test(r.kind)),
      advisoryTriggered: false };
    // Re-read the complete persisted log; retain the actual analyzer's summary and findings.
    session.runtime = analyzeWatchLog(rows);
  } catch (error) { status.watch = { error: error.message, hookObserved: hooked, advisoryTriggered: false }; }
  finally { clearTimeout(outerTimer); clearTimeout(stopTimer); }
  status.shipped.asarSha256After = await hash(installer.code);
  status.shipped.executableSha256After = await hash(installer.mainExe);
  status.shipped.unchanged = status.shipped.asarSha256Before === status.shipped.asarSha256After &&
    status.shipped.executableSha256Before === status.shipped.executableSha256After;
  if (!status.shipped.unchanged) throw Error('Shipped code changed during observation; pinned-release report would be invalid');
  persist();
  console.log('Scanning shipped code and querying dependency advisories');
  scan = await run({
    input: installer.code, installer, runtime: session?.runtime, runtimeElectronVersion: session?.watchDiagnostics?.electron,
    watchDiagnostics: session?.watchDiagnostics, isRelative: true, nvd: false, checkLinks: false,
    reportsBase: out, output: [path.join(out, 'report.html'), path.join(out, 'report.json'), path.join(out, 'components.xlsx')],
    diagnostics: path.join(out, 'diagnostics.json'),
  });
  status.scan = { electron: scan.electronVersion, electronVersionSource: scan.electronVersionSource,
    errors: scan.errors, findings: scan.reported.length,
    components: scan.dependencies?.rows.length,
    componentsWithAdvisories: scan.dependencies?.rows.filter(r => r.advisories?.length).length,
    dependencyLookupErrors: scan.dependencies?.errors,
    advisoryRelevantFindingIds: [...new Set(scan.reported.filter(i => spec.advisory.expectedChecks.includes(i.id)).map(i => i.id))],
    html: 'report.html', json: 'report.json', componentsWorkbook: 'components.xlsx',
    markdownFindings: scan.reports.findings.map(f => path.relative(out, f)),
  };
  status.finishedAt = new Date().toISOString(); persist();
  const readme = [
    '# ' + spec.name + ' ' + spec.version + ' — Windows validation',
    '',
    'Selected advisory: [' + spec.advisory.id + '](' + spec.advisory.url + '). ' + spec.advisory.summary + '.',
    '',
    '## Deliverables', '',
    '- report.html: full Electronegativity report.',
    '- report.json: report data, runtime evidence and dependency intelligence.',
    '- components.xlsx: components needing action and the full component catalog.',
    '- reports/: one client finding per Markdown file plus the same components workbook for relative links.',
    '- testerNotes/: supporting review notes for each client finding.',
    '- session.jsonl: raw tool watch/proof log (when instrumentation completed).',
    '- validation.json and diagnostics.json: provenance, proof outcomes and coverage/errors.',
    '',
    '## Actual environment', '',
    JSON.stringify(status.runner, null, 2), '',
    'Scanner: ' + config.scannerCommit + '. Release SHA-256: ' + status.package.sha256 + '.',
    'Shipped manifest version and executable architecture verified. Executable and app.asar hashes unchanged through watch.',
    '',
    '## Coverage limits', '',
    ...status.limits.map(s => '- ' + s),
    '',
    'Advisory-relevant check families observed: ' + (status.scan.advisoryRelevantFindingIds.join(', ') || 'none') + '.',
    'These are supporting signals, not advisory reproduction or an estimate of tool precision/recall.',
  ].join('\n');
  fs.writeFileSync(path.join(out, 'README.md'), readme + '\n');
  console.log(JSON.stringify({ app: spec.id, scan: status.scan, hook: session?.watchDiagnostics?.hookStarted }, null, 2));
  if (!session?.watchDiagnostics?.hookStarted || scan.errors.some(e => !e.tolerable)) process.exitCode = 1;
} catch (error) {
  status.error = { message: error.message, stack: error.stack }; status.finishedAt = new Date().toISOString(); persist();
  console.error(error); process.exitCode = 1;
}
