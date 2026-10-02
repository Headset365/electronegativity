import fs from 'node:fs';
import { searchRoots, snapshot, changedFiles, scanForCanaries } from '../storage/canary.js';
import { readWatchLog } from './analyze.js';

// One terminal input owner during logout checkpoints. The hook reads live cookies;
// the CLI reads only app-scoped files and supplied markers. No live credentials are tried.
export function logoutCheck({ ask, commands, log, canaries = [], searchDirs = [] }) {
  let stopped = false;
  const write = data => fs.appendFileSync(log, JSON.stringify({ t: Date.now(), ...data }) + '\n');
  const waitSnapshot = phase => new Promise(resolve => {
    const started = Date.now();
    const timer = setInterval(() => {
      if (stopped || Date.now() - started > 20000) { clearInterval(timer); resolve(false); return; }
      if (readWatchLog(log).some(r => r.kind === 'logout-snapshot' && r.phase === phase && r.t >= started)) { clearInterval(timer); resolve(true); }
    }, 200);
  });
  const task = (async () => {
    if (!ask) { write({ kind: 'proof', test: 'logout', outcome: 'skipped', reason: 'interactive terminal required' }); return; }
    const beforeAnswer = await ask('Logout check: sign in and finish the test workflow. Type BEFORE to capture the signed-in state (or SKIP).');
    if (stopped || beforeAnswer?.toUpperCase() !== 'BEFORE') return;
    const paths = readWatchLog(log).filter(r => r.kind === 'paths').pop() || {};
    const roots = searchRoots([], { extra: [...searchDirs, ...['userData', 'logs', 'crashDumps'].map(k => paths[k]).filter(Boolean)] });
    const beforeFiles = snapshot(roots);
    const beforeHits = canaries.length ? scanForCanaries(roots, canaries).hits.map(h => h.location) : [];
    fs.appendFileSync(commands, JSON.stringify({ kind: 'logout-snapshot', phase: 'before' }) + '\n');
    const beforeComplete = await waitSnapshot('before');
    if (!beforeComplete || stopped) { write({ kind: 'proof', test: 'logout', outcome: 'inconclusive', reason: 'before snapshot did not complete' }); return; }
    const afterAnswer = await ask('Signed-in snapshot captured. Log out using the app, wait for logout to finish, then type AFTER (or SKIP).');
    if (stopped || afterAnswer?.toUpperCase() !== 'AFTER') return;
    fs.appendFileSync(commands, JSON.stringify({ kind: 'logout-snapshot', phase: 'after' }) + '\n');
    const afterComplete = await waitSnapshot('after');
    if (stopped) return;
    const afterHits = canaries.length ? scanForCanaries(roots, canaries).hits.map(h => h.location) : [];
    write({ kind: 'logout-files', complete: beforeComplete && afterComplete, roots: roots.length,
      retained: [...new Set(afterHits.filter(h => beforeHits.includes(h)))], changed: changedFiles(beforeFiles, snapshot(roots)).slice(0, 200),
      canaries: canaries.length, limitations: 'Bounded file markers only; encrypted values are not decrypted, and unchanged files need not contain authentication data.' });
  })().catch(() => { if (!stopped) write({ kind: 'proof', test: 'logout', outcome: 'error' }); });
  return { stop: () => { stopped = true; }, task };
}
