// One watch session (or a saved session log) turned into what the scan needs: the runtime findings, what the hook
// recorded for --diagnostics, and the front-end code captured from the server (plus --remote URLs) to scan with the app.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import chalk from 'chalk';
import { resolveApp, watchApp } from './launch.js';
import { locateApp } from './locate.js';
import { readWatchLog, analyzeWatchLog } from './analyze.js';
import { analyzePackagedFuses } from './fuses.js';
import { crawl } from '../remote/fetch.js';
import { prepareScanFolder } from '../remote/sources.js';

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
export async function observeSession({ watch, watchLog, args = [], marker, capture = true }) {
  let log = watchLog;
  let packagedApp;
  let staticInput;
  if (watch) {
    const located = locateApp(watch);
    const app = resolveApp(located.kind === 'project' ? located.folder : located.executable, args);
    packagedApp = app.packaged ? app.command : undefined;
    staticInput = located.code;
    console.log(chalk.cyan(__('watchStarting')));
    log = await watchApp(located.kind === 'project' ? located.folder : located.executable, { args, marker, capture });
    console.log(chalk.gray(__('watchLogSaved', { file: log })));
  }
  const records = readWatchLog(log);
  const runtime = analyzeWatchLog(records);
  // for --diagnostics: what the hook captured, by kind, and anything that went wrong inside it
  const recordKinds = {};
  for (const record of records) recordKinds[record.kind] = (recordKinds[record.kind] || 0) + 1;
  const start = records.find(r => r.kind === 'start');
  const watchDiagnostics = {
    mode: watch ? 'launched' : 'log', packaged: !!packagedApp, hookStarted: !!start, lateStart: !!(start && start.late),
    electron: start && start.electron, marker: !!marker, records: recordKinds,
    hookErrors: records.filter(r => r.kind === 'hook-error').slice(0, 20).map(r => r.message), summary: { ...runtime.summary, fuses: undefined },
  };
  // read the fuses actually written into the packaged binary, which the static FUSES_* checks can't see
  if (packagedApp) {
    const fuses = analyzePackagedFuses(packagedApp);
    if (fuses.read) {
      runtime.issues.push(...fuses.issues);
      runtime.summary.fuses = fuses.states;
    } else console.error(chalk.yellow(__('watchFusesUnreadable', { file: fuses.binary })));
    watchDiagnostics.fusesRead = fuses.read;
  }
  if (!runtime.summary.started) console.error(chalk.yellow(__('watchNoHook')));
  return { runtime, watchDiagnostics, watchLog: log, staticInput };
}

/**
 * Front-end code served over the network: what a watch session captured (capture/ next to its log) and `remote` URLs,
 * downloaded and prepared for scanning. Returns { extraInputs, remoteDiagnostics, scanDir }.
 */
export async function collectRemote({ watchLog, capture = true, remote = [], headers = {}, offline = false }) {
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
  if (prepared) {
    extraInputs.push(prepared);
    remoteDiagnostics.scanned = prepared.counts;
    console.log(chalk.gray(__('remoteScanning', { count: prepared.labels.size, dir })));
  }
  return { extraInputs, remoteDiagnostics, scanDir: prepared && prepared.dir };
}
