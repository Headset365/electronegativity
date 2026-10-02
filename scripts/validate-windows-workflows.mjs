// Native Windows release validation through the actual CLI and an interactive ConPTY.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { createRequire } from 'node:module';
import { unpackTarget } from '../src/unpack/index.js';
import { readManifest } from '../src/watch/launch.js';
import { connect, until, delay } from './windows-cdp-client.mjs';
const require = createRequire(import.meta.url);
const pty = require('node-pty');
const config = JSON.parse(fs.readFileSync(new URL('./windows-workflow-apps.json', import.meta.url)));
const spec = config.apps.find(a => a.id === process.argv[2]);
if (!spec || process.platform !== 'win32') throw Error('Native Windows and a configured app are required');
const repo = path.resolve(import.meta.dirname, '..');
const out = path.join(repo, 'workflow-results', spec.id);
const work = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'eng-workflow-' + spec.id);
fs.mkdirSync(out, { recursive: true }); fs.mkdirSync(work, { recursive: true });
const marker = `ENG_${spec.id.toUpperCase()}_20261002`;
const status = { app: spec.name, version: spec.version, advisory: spec.advisory, marker, startedAt: new Date().toISOString(), baselineScannerCommit: config.baselineScannerCommit,
  scannerCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), runner: { platform: process.platform, release: os.release(), node: process.version, image: process.env.ImageOS, imageVersion: process.env.ImageVersion },
  scope: 'Shipped Windows release, native watch proofs, renderer interaction and disposable local content', steps: [],
  limits: ['Hosted Windows Server is the actual test OS.', 'Packages are extracted rather than installed; ACLs describe the extraction folder.', 'Only generated local test data is used; no live client credentials are validated.', 'Advisory reproduction requires a payload execution signal; static findings alone do not reproduce a CVE.'] };
const persist = () => fs.writeFileSync(path.join(out, 'validation.json'), JSON.stringify(status, null, 2));
const step = (name, data) => { status.steps.push({ name, at: new Date().toISOString(), ...data }); persist(); console.log(name + ': ' + JSON.stringify(data).slice(0,600)); };
async function hash(file) {
  const h = crypto.createHash('sha256');
  if (fs.statSync(file).isDirectory()) {
    const names = fs.readdirSync(file, { recursive: true }).filter(n => fs.statSync(path.join(file,n)).isFile()).sort();
    for (const name of names) { h.update(name.replaceAll('\\','/')); h.update(await hash(path.join(file,name))); }
  } else for await (const chunk of fs.createReadStream(file)) h.update(chunk);
  return h.digest('hex');
}
async function freePort() { const s = net.createServer(); await new Promise(resolve => s.listen(0, '127.0.0.1', resolve)); const port = s.address().port; await new Promise(resolve => s.close(resolve)); return port; }
function logs() { return fs.readdirSync(os.tmpdir()).filter(n => n.startsWith('electronegativity-watch-')).map(n => path.join(os.tmpdir(), n, 'session.jsonl')).filter(f => fs.existsSync(f) && fs.statSync(f).mtimeMs >= Date.parse(status.startedAt)); }
function rows() { return logs().flatMap(file => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).flatMap(l => { try { return [JSON.parse(l)]; } catch { return []; } })); }
function ownedMainPID() { return rows().find(r => r.kind === 'proof-listener' && r.purpose === 'certificate' && Number.isInteger(r.pid))?.pid; }
async function snapshot(cdp, name) { fs.writeFileSync(path.join(out, name + '.json'), JSON.stringify(await cdp.state(), null, 2)); await cdp.screenshot(path.join(out, name + '.png')); }
let cli, cdp, installer;
try {
  const packageFile = path.join(work, spec.asset);
  console.log('Download ' + spec.url);
  const r = await fetch(spec.url, { signal: AbortSignal.timeout(240000) }); if (!r.ok) throw Error('Download HTTP ' + r.status);
  await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(packageFile));
  status.package = { url: spec.url, sha256: await hash(packageFile), expectedSha256: spec.sha256 }; persist();
  if (status.package.sha256 !== spec.sha256) throw Error('Release digest mismatch');
  installer = unpackTarget(packageFile, { workDir: path.join(work, 'extracted') });
  if (!installer.code || !installer.mainExe) throw Error('Shipped Electron layout not found');
  const manifest = readManifest(installer.code);
  status.shipped = { executable: installer.mainExe, manifestVersion: manifest.version, codeHashBefore: await hash(installer.code), exeHashBefore: await hash(installer.mainExe) };
  if (String(manifest.version) !== spec.version) throw Error('Shipped version mismatch ' + manifest.version);
  const debugPort = await freePort(), apiPort = await freePort();
  const appArgs = [`--remote-debugging-port=${debugPort}`];
  const env = { ...process.env, NODE_OPTIONS: '', ENG_VALIDATION_MARKER: marker };
  if (spec.id === 'trilium') { env.TRILIUM_DATA_DIR = path.join(work, 'dataset'); env.TRILIUM_NETWORK_PORT = String(apiPort); env.TRILIUM_NETWORK_HOST = '127.0.0.1'; }
  if (spec.id === 'siyuan') { appArgs.push(`--workspace=${path.join(work, 'workspace')}`, `--port=${apiPort}`); fs.mkdirSync(path.join(work, 'workspace'), { recursive: true }); }
  if (spec.id === 'notesnook') env.PORTABLE_EXECUTABLE_DIR = work;
  // Use the app's own onboarding handler to create a disposable workspace before
  // the measured CLI session. First-launch SiYuan ignores --workspace/--port.
  if (spec.id === 'siyuan') {
    const setup = spawn(installer.mainExe, appArgs, { env, stdio: ['ignore','pipe','pipe'] });
    setup.stdout.on('data', d => fs.appendFileSync(path.join(out, 'setup-app.log'), d));
    setup.stderr.on('data', d => fs.appendFileSync(path.join(out, 'setup-app.log'), d));
    const initial = await connect(debugPort, t => t.url.includes('init.html') || t.url.includes('/stage/build/app/'), 90000);
    if (initial.target.url.includes('init.html')) {
      await initial.eval(`require('electron').ipcRenderer.send('siyuan-first-init',{workspace:${JSON.stringify(path.join(work,'workspace'))},lang:'en_US'}); true`);
      initial.close();
      const ready = await connect(debugPort, t => t.url.includes('/stage/build/app/'), 120000);
      await snapshot(ready, 'workspace-onboarding'); ready.close();
    } else initial.close();
    execFileSync('taskkill', ['/PID', String(setup.pid), '/T', '/F']);
    await delay(3000);
    step('app-onboarding', { method: 'Shipped first-run workspace handler, without test payloads', workspace: path.join(work,'workspace') });
  }
  const remote = spec.id === 'notesnook' ? 'https://app.notesnook.com/' : `http://127.0.0.1:${apiPort}/`;
  const args = ['--max-old-space-size=6144', 'src/index.js', '--app', installer.mainExe, '-o', 'report.html,report.json,components.xlsx', '--out', out,
    '--all-files', '--auto-campaign', '--user-data', 'auto', '--watch-screenshots', 'screenshots', '--remote', remote, '--remote-header', 'Cookie', '--watch-marker', marker, '--prove', '--sessions', '1', '--watch-args', appArgs.join(' '), '--no-nvd', '--no-source-maps'];
  status.command = { executable: 'node', args, effectiveCLI: args.slice(1), remote, headerNames: ['Cookie'], addedOptions: ['--sessions 1', '--no-nvd', '--no-source-maps', '--watch-args (local renderer debug port and isolated app data)'], customExploits: false }; persist();
  const terminal = pty.spawn(process.execPath, args, { name: 'xterm-color', cols: 180, rows: 45, cwd: repo, env, useConpty: true }); cli = terminal;
  let transcript = '', promptOffset = 0, exited = false, exitCode;
  const finished = new Promise(resolve => terminal.onExit(e => { exited = true; exitCode = e.exitCode; resolve(e); }));
  terminal.onData(data => {
    transcript += data; fs.appendFileSync(path.join(out, 'cli-transcript.txt'), data);
    const clean = transcript.slice(promptOffset).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
    if (!clean.includes('> ')) return;
    const q = clean.slice(clean.lastIndexOf('[validate]'));
    let answer;
    if (/Fields to test/.test(q)) answer = clean.includes('/api/block/updateBlock') ? 'data' : '';
    else if (/Saved-content view URL/.test(q)) answer = status.savedView || '';
    else if (/Run \d+ cases/.test(q)) answer = q.includes('/api/block/updateBlock') ? 'y' : 'n';
    else if (/Send .*\[y\/N\]/.test(q)) answer = 'n';
    if (answer !== undefined) { promptOffset = transcript.length; step('interactive-prompt', { question: q.slice(0,1200), answer, policy: 'Only the reviewed disposable updateBlock content route may run an automatic campaign' }); terminal.write(answer + '\r'); }
  });
  cdp = await Promise.race([
    connect(debugPort, t => spec.id !== 'siyuan' || t.url.includes('/stage/build/app/'), 900000, () => exited),
    finished.then(e => { throw Error('CLI exited before renderer attachment (code ' + e.exitCode + '): ' + transcript.slice(-3000)); })
  ]); step('renderer-debugger-connected', { url: cdp.target.url, nativeProofsAlsoEnabled: true });
  await delay(4000); await snapshot(cdp, 'initial-renderer');
  if (spec.id === 'siyuan') {
    const api = async (route, data) => cdp.eval(`fetch(${JSON.stringify(route)},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(${JSON.stringify(data)})}).then(r=>r.json())`);
    await until(() => cdp.eval('!!window.siyuan && !!window.siyuan.config'), 'SiYuan main UI', 120000);
    await cdp.eval(`document.cookie='eng_validation_cookie=${marker}; SameSite=Strict; path=/'`);
    const nb = await api('/api/notebook/createNotebook', { name: 'ENG disposable validation' }); step('create-disposable-notebook', { result: nb });
    if (nb.code !== 0 || !nb.data?.notebook?.id) throw Error('Notebook creation failed');
    const doc = await api('/api/filetree/createDocWithMd', { notebook: nb.data.notebook.id, path: '/ENG campaign', markdown: 'Original disposable content' }); step('create-disposable-note', { result: doc });
    if (doc.code !== 0 || typeof doc.data !== 'string') throw Error('Document creation failed');
    status.noteId = doc.data; status.savedView = `http://127.0.0.1:${apiPort}/stage/build/app/?id=${doc.data}`; persist();
    await cdp.eval(`document.querySelector('[data-type="close"]')?.click(); document.querySelector('[aria-label="Close"]')?.click();`);
    const seed = await api('/api/block/updateBlock', { id: doc.data, dataType: 'markdown', data: 'Original disposable content' }); step('auto-campaign-seed-save', { result: seed, noteId: doc.data });
    await until(() => rows().find(r => r.kind === 'campaign-done'), 'Completed automatic campaign', 240000);
    step('auto-campaign-completed', { done: rows().filter(r => r.kind === 'campaign-done'), sends: rows().filter(r => r.kind === 'campaign-send').length, restores: rows().filter(r => r.kind === 'campaign-restore') });
    const read = await api('/api/block/getBlockKramdown', { id: doc.data }); step('independent-restoration-readback', { result: read, originalPresent: JSON.stringify(read).includes('Original disposable content') });
    await snapshot(cdp, 'after-campaign');
  } else if (spec.id === 'trilium') {
    const url = await cdp.eval('location.href');
    if (url.includes('/setup')) { step('initialize-disposable-dataset', { result: await cdp.eval(`fetch('/api/setup/new-document',{method:'POST'}).then(r=>({status:r.status}))`) }); await cdp.eval(`location.replace('/setup'); true`); cdp.close(); await delay(5000); cdp = await connect(debugPort, t => !t.url.includes('/setup'), 90000); }
    await snapshot(cdp, 'ready-renderer');
    step('app-specific-workflow-prepared', { state: await cdp.eval(`({glob:!!window.glob,globals:Object.keys(window).filter(k=>/trilium|note|appContext/i.test(k))})`) });
    await until(() => cdp.eval('!!window.glob?.appContext?.tabManager'), 'Trilium note UI', 90000);
    await cdp.eval(`window.glob.appContext.triggerCommand('createNoteIntoInbox'); true`);
    await until(() => cdp.eval(`!!document.querySelector('input.note-title')`), 'Trilium title editor');
    await cdp.eval(`const e=document.querySelector('input.note-title'); e.focus(); e.select(); true`);
    await cdp.send('Input.insertText', { text: 'Disposable note ' + marker });
    await cdp.eval(`document.querySelector('input.note-title').blur(); true`); await delay(2500);
    step('normal-note-save', { note: await cdp.eval(`({id:glob.getActiveContextNote()?.noteId,title:glob.getActiveContextNote()?.title,url:location.href})`), path: 'Shipped create-note command and title input; no custom payload' });
    await snapshot(cdp, 'saved-note');
  } else {
    await snapshot(cdp, 'ready-renderer');
    step('app-specific-workflow-prepared', { state: await cdp.eval(`({globals:Object.keys(window).filter(k=>/db|database|store|webpack/i.test(k)),buttons:[...document.querySelectorAll('button')].map(e=>e.innerText).slice(0,30)})`) });
  }
  await delay(5000);
  step('native-proof-results', { proofs: rows().filter(r => r.kind === 'proof') });
  await snapshot(cdp, 'final-renderer');
  const pid = ownedMainPID();
  if (pid) { try { execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { encoding: 'utf8' }); } catch {} }
  else { try { await cdp.send('Browser.close'); } catch {} }
  cdp.close(); cdp = undefined;
  let reportTimer;
  try { await Promise.race([finished, new Promise((_,reject) => { reportTimer = setTimeout(() => reject(Error('Final report generation timed out')), 600000); reportTimer.unref(); })]); }
  finally { clearTimeout(reportTimer); }
  status.cliExitCode = exitCode;
  for (const [i,file] of logs().entries()) fs.copyFileSync(file, path.join(out, `session-${i+1}.jsonl`));
  status.runtimeCounts = Object.fromEntries([...new Set(rows().map(r=>r.kind))].map(k=>[k,rows().filter(r=>r.kind===k).length]));
  status.shipped.codeHashAfter = await hash(installer.code); status.shipped.exeHashAfter = await hash(installer.mainExe);
  status.shipped.unchanged = status.shipped.codeHashBefore === status.shipped.codeHashAfter && status.shipped.exeHashBefore === status.shipped.exeHashAfter;
  status.completeReports = ['report.html','report.json','components.xlsx'].every(f => fs.existsSync(path.join(out,f)));
  status.finishedAt = new Date().toISOString(); persist();
  if (exitCode !== 0 || !status.completeReports || !status.shipped.unchanged) process.exitCode = 1;
} catch (error) {
  status.error = { message: error.message, stack: error.stack }; persist(); console.error(error);
  if (cdp) { try { await snapshot(cdp, 'failure-renderer'); } catch {} cdp.close(); }
  const pid = ownedMainPID();
  if (pid) { try { execFileSync('taskkill', ['/PID', String(pid), '/T', '/F']); } catch {} }
  if (cli) { await delay(15000); cli.kill(); }
  for (const [i,file] of logs().entries()) fs.copyFileSync(file, path.join(out, `session-${i+1}.jsonl`));
  process.exitCode = 1;
}
// ConPTY owns native handles; after reports/logs are flushed, end the harness
// explicitly rather than leaving the CI job alive because of terminal helpers.
fs.writeFileSync(path.join(out, 'exit-status.json'), JSON.stringify({ exitCode: process.exitCode || 0, finishedAt: new Date().toISOString() }));
process.exit(process.exitCode || 0);
