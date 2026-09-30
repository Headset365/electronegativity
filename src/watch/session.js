// One watch session (or a saved session log) turned into what the scan needs: the runtime findings, what the hook
// recorded for --diagnostics, and the front-end code captured from the server (plus --remote URLs) to scan with the app.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import chalk from 'chalk';
import { resolveApp, watchApp, readManifest } from './launch.js';
import { credentialBaseline, appNames } from '../storage/index.js';
import { locateApp } from './locate.js';
import { readWatchLog, analyzeWatchLog } from './analyze.js';
import { analyzePackagedFuses, readFuseWire, fuseBinaryFor } from './fuses.js';
import { crawl } from '../remote/fetch.js';
import { prepareScanFolder, mapFrames } from '../remote/sources.js';
import { createAssistant, followLog, writeMarkerFiles } from './assistant.js';
import { watchDebug } from './debug.js';
import { watchDebugApp } from './debug_launch.js';

export function parseHeaders(list = []) {
  const headers = {};
  for (const header of list) {
    const at = header.indexOf(':');
    if (at > 0) headers[header.slice(0, at).trim()] = header.slice(at + 1).trim();
  }
  return headers;
}

/**
 * Runs the app at `watch` (install folder, executable or project folder) with the hook until it is closed, or reads the
 * session log `watchLog`, and analyzes it. Returns { runtime, watchDiagnostics, watchLog, staticInput }.
 * @throws when the app can't be started or the log can't be read
 */
export async function observeSession({ watch, watchLog, args = [], debugUrl, debugLaunch = false, debugTarget, debugDuration = 0, marker, active = false, campaign, autoCampaign = false, capture = true, traffic = true, scope = [], reveal = false, canaries = [], searchDirs = [], userData,
  assistant, staticIssues = [], confirm, screenshots }) {
  let log = watchLog;
  let packagedApp;
  let injection;
  let staticInput;
  let credentials;
  const rendererDebug = !!debugUrl || debugLaunch;
  if (debugLaunch && (!watch || debugUrl || watchLog)) throw new Error('--debug-launch requires an app to launch and cannot be combined with a saved log or --debug-url');
  if (rendererDebug && campaign && (campaign.mode !== 'capture' || campaign.docxImport || campaign.cases.some(name => /^(api|nav)-/.test(name))))
    throw new Error('Renderer debugging needs a standard capture campaign or --auto-campaign; direct request, API, navigation and DOCX profiles use native watch mode');
  if (watch) {
    const located = locateApp(watch);
    const app = debugUrl ? undefined : resolveApp(located.kind === 'project' ? located.folder : located.executable, args);
    packagedApp = debugUrl ? (located.kind === 'project' ? undefined : located.executable) : app.packaged ? app.command : undefined;
    staticInput = located.code;
    // a packaged app gets the observer through the Node inspector: a build that switched it off can't be observed
    const wire = packagedApp && !rendererDebug ? readFuseWire(fuseBinaryFor(packagedApp)) : undefined;
    if (wire && wire.config.EnableNodeCliInspectArguments === false) {
      console.error(chalk.yellow(__('watchInspectFuseOff')));
      injection = { method: 'inspector', blockedByFuse: true };
    }
    // --canary: record the app's folders and the Credential Manager first, to show afterwards what the session wrote
    if (canaries.length > 0) {
      const names = appNames(readManifest(located.code), [located.name]);
      credentials = { names, installDir: located.kind === 'project' ? undefined : located.folder,
        baseline: credentialBaseline({ names, searchDirs, userData, installDir: located.kind === 'project' ? undefined : located.folder }) };
    }
    console.log(chalk.cyan(__('watchStarting')));
    // the validation assistant follows the session as it happens: what to try next, what the marker has shown
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-watch-'));
    const logFile = path.join(logDir, 'session.jsonl');
    if (!assistant) {
      let profileCount = 0;
      assistant = createAssistant({ marker, active, campaign, autoCampaign, scope,
        saveCampaign: profile => { const file = path.join(logDir, `campaign-${++profileCount}.json`); fs.writeFileSync(file, JSON.stringify(profile, null, 2)); return file; },
        staticIssues, files: marker ? writeMarkerFiles(logDir, marker, active) : undefined });
      assistant.intro();
    }
    fs.writeFileSync(logFile, '');
    // when the terminal is interactive and there is a marker, let the assistant re-send the marker request itself
    // (after a Y/N): it writes a command here and the hook, reading it, replays the request through the app's session
    let commandsFile;
    if (marker && (confirm || campaign) && assistant.useChannel) {
      commandsFile = path.join(logDir, 'commands.jsonl');
      fs.writeFileSync(commandsFile, '');
      assistant.useChannel({ confirm, ask: confirm?.ask, cancel: typeof confirm?.cancel === 'function' ? () => confirm.cancel() : undefined,
        send: (command) => { try { fs.appendFileSync(commandsFile, JSON.stringify(command) + '\n'); } catch { /* best effort */ } } });
      if (campaign?.mode === 'request' || campaign?.mode === 'docx')
        fs.appendFileSync(commandsFile, JSON.stringify({ kind: 'run-campaign', profile: campaign }) + '\n');
    }
    const stopFollowing = followLog(logFile, record => assistant.handle(record));
    try {
      const debugOptions = { target: debugTarget, duration: debugDuration, marker, active, campaign: !!campaign || autoCampaign,
        traffic, scope, reveal, screenshots, log: logFile, commands: commandsFile };
      log = debugUrl ? await watchDebug(debugUrl, debugOptions) : debugLaunch ? await watchDebugApp(located.kind === 'project' ? located.folder : located.executable,
        { ...debugOptions, args, onNote: note => { injection = note; } }) : await watchApp(located.kind === 'project' ? located.folder : located.executable, { args, marker, active, campaign: !!campaign || autoCampaign, capture, traffic, scope, reveal, screenshots, log: logFile, commands: commandsFile,
        onNote: (note) => { injection = { ...injection, ...note }; } });
    } finally {
      stopFollowing();
      if (assistant.clearChannel) assistant.clearChannel();
      if ((campaign || autoCampaign) && commandsFile) try { fs.unlinkSync(commandsFile); } catch { /* best effort */ }
    }
    assistant.printSummary();
    console.log(chalk.gray(__('watchLogSaved', { file: log })));
  }
  const records = readWatchLog(log);
  if (campaign && !records.some(r => r.kind === (campaign.mode === 'docx' ? 'docx-done' : 'campaign-done') || r.kind === 'campaign-error'))
    records.push({ kind: 'campaign-error', message: 'No completed campaign was observed; check the app hook, test window and capture workflow' });
  if (campaign?.docxImport && !records.some(r => r.kind === 'docx-done' || r.kind === 'campaign-error'))
    records.push({ kind: 'campaign-error', message: 'The configured DOCX import campaign did not complete' });
  const runtime = analyzeWatchLog(records);
  // for --diagnostics: what the hook captured, by kind, and anything that went wrong inside it
  const recordKinds = {};
  for (const record of records) recordKinds[record.kind] = (recordKinds[record.kind] || 0) + 1;
  const start = records.find(r => r.kind === 'start');
  const watchDiagnostics = {
    mode: debugUrl ? 'debug-attached' : debugLaunch ? 'debug-launched' : watch ? 'launched' : 'log', packaged: !!packagedApp, hookStarted: !!start && !rendererDebug, lateStart: !!(start && start.late),
    electron: start && start.electron, markerSet: !!marker, activeTests: active, campaign: campaign && { mode: campaign.mode, route: campaign.route, cases: campaign.cases }, records: recordKinds,
    hookErrors: records.filter(r => r.kind === 'hook-error').slice(0, 20).map(r => r.message),
    // field names stay out of the shared diagnostics: only how many there were and whether the marker was sent
    summary: { ...runtime.summary, fuses: undefined, api: runtime.summary.api.map(({ fields, ...endpoint }) => ({ ...endpoint, fields: fields.length, markerSent: fields.some(f => f.marker) })) },
    marker: { ...Object.fromEntries(['sink', 'shell', 'will-navigate', 'window-open', 'ipc', 'process'].map(kind => [kind, records.filter(r => r.kind === kind && (r.marker || (kind === 'sink' && r.live))).length])) },
    // how the observer was loaded: NODE_OPTIONS for an app folder, the Node inspector for a packaged app
    injection: rendererDebug ? { ...injection, method: 'renderer-cdp', loaded: !!start, mainProcess: false } : packagedApp ? { method: 'inspector', ...injection } : watch ? { method: 'NODE_OPTIONS' } : undefined,
    debugCoverage: records.filter(record => record.kind === 'debug-coverage').map(record => record.message),
    // the traffic checks that ran inside the app: how much they saw, from which sources (no hosts: they identify the app)
    traffic: runtime.summary.traffic && { http: runtime.summary.traffic.http, ws: runtime.summary.traffic.ws, hosts: runtime.summary.traffic.hosts,
      sources: runtime.summary.traffic.sources, findings: runtime.summary.traffic.findings, notes: runtime.summary.traffic.notes.length },
  };
  // read the fuses actually written into the packaged binary, which the static FUSES_* checks can't see
  if (packagedApp) {
    const fuses = analyzePackagedFuses(packagedApp);
    if (fuses.read) {
      runtime.issues.push(...fuses.issues);
      runtime.summary.fuses = fuses.states;
      watchDiagnostics.fuses = fuses.states;
    } else console.error(chalk.yellow(__('watchFusesUnreadable', { file: fuses.binary })));
    watchDiagnostics.fusesRead = fuses.read;
  }
  if (!runtime.summary.started && !(watch && injection && injection.loaded)) console.error(chalk.yellow(__('watchNoHook')));
  // the observer was in, but the app never opened a window: usually another copy of it was still running (a second
  // instance hands over to the first and exits), or it closed on its own
  else if (watch && runtime.summary.windows === 0) {
    console.error(chalk.yellow(__('watchNoWindows')));
    watchDiagnostics.noWindows = true;
  }
  return { runtime, watchDiagnostics, watchLog: log, staticInput, credentials };
}

/**
 * Front-end code served over the network: what a watch session captured (capture/ next to its log) and `remote` URLs,
 * downloaded and prepared for scanning. Returns { extraInputs, remoteDiagnostics, scanDir }.
 */
export async function collectRemote({ watchLog, capture = true, remote = [], headers = {}, offline = false, runtime }) {
  const extraInputs = [];
  const captureDir = capture && watchLog ? path.join(path.dirname(watchLog), 'capture') : undefined;
  const hasCapture = !!captureDir && fs.existsSync(captureDir);
  if (remote.length === 0 && !hasCapture) return { extraInputs };
  const dir = hasCapture ? captureDir : fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-remote-'));
  const remoteDiagnostics = { seeds: remote.length, fromWatch: hasCapture, headers: Object.keys(headers) };
  try {
    if (offline && remote.length > 0) console.error(chalk.yellow(__('remoteOffline')));
    if (!offline) {
      console.log(chalk.cyan(__('remoteFetching')));
      const stats = await crawl(dir, remote, { headers });
      remoteDiagnostics.fetch = { fetched: stats.fetched, notFound: stats.notFound, skipped: stats.skipped, failed: stats.failed.slice(0, 20) };
      for (const failure of stats.failed.slice(0, 10)) console.error(chalk.yellow(__('remoteFetchFailed', { url: failure.url, message: failure.message })));
    }
  } catch (error) {
    remoteDiagnostics.error = String(error.message);
    console.error(chalk.yellow(__('remoteFetchFailed', { url: remote[0] || 'capture', message: error.message })));
  }
  const prepared = prepareScanFolder(dir);
  // script locations the marker was written from, translated to the original sources the scan reports on
  if (hasCapture && runtime) for (const issue of runtime.issues.filter(i => i.id === 'RUNTIME_MARKER_SINK')) mapFrames(captureDir, issue.properties.frames);
  if (prepared) {
    extraInputs.push(prepared);
    remoteDiagnostics.scanned = prepared.counts;
    console.log(chalk.gray(__('remoteScanning', { count: prepared.labels.size, dir })));
  }
  return { extraInputs, remoteDiagnostics, scanDir: prepared && prepared.dir };
}
