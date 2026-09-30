// Owns the app process and its local renderer debugger for a single managed run.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { resolveApp, freePort } from './launch.js';
import { connectDebug, watchDebug } from './debug.js';

export async function watchDebugApp(target, { args = [], target: debugTarget, duration = 0, log, stdio = 'inherit', onNote = () => {},
  spawnApp = spawn, connect = connectDebug, observe = watchDebug, selectPort = freePort, startupTimeout = 30000, ...options } = {}) {
  if (!log) throw new Error('Managed debug launch requires a session log');
  if (!Number.isInteger(startupTimeout) || startupTimeout < 1) throw new Error('Debug startup timeout must be positive');
  if (!Number.isInteger(duration) || duration < 0 || duration > 86400) throw new Error('Debug duration must be 0–86400 seconds');
  if (args.some(arg => /^--remote-debugging-(port|address|pipe)(?:=|$)/.test(arg)))
    throw new Error('--debug-launch manages its own debug port; remove remote-debugging flags from --watch-args');
  const app = resolveApp(target, args);
  const port = await selectPort();
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Could not allocate a local debug port');
  const endpoint = `http://127.0.0.1:${port}`;
  fs.writeFileSync(log, '');
  // Electron's DevTools socket factory binds the renderer debug listener to 127.0.0.1.
  const child = spawnApp(app.command, [...app.args, `--remote-debugging-port=${port}`], { env: { ...process.env }, stdio });
  let client, exited = false, launchError, finishing = false, finish;
  const ended = new Promise(resolve => { finish = resolve; });
  const exit = error => { exited = true; launchError = error; client?.close(); finish(); };
  child.once('error', exit);
  child.once('exit', () => exit());
  const stop = () => { finishing = true; client?.close(); if (!exited) child.kill(); };
  process.once('SIGINT', stop);
  const deadline = Date.now() + startupTimeout;
  let lastError, startupTimer;
  const timedOut = new Promise((resolve, reject) => {
    startupTimer = setTimeout(() => reject(Object.assign(new Error('Renderer debug startup timed out; the app may ignore debug launch options or hand off to an existing instance'),
      { code: 'ENG_DEBUG_STARTUP_TIMEOUT' })), startupTimeout);
  });
  timedOut.catch(() => {}); // a synchronous spawn/connect failure may end the run before a race is installed
  try {
    while (!client && !exited && !finishing && Date.now() < deadline) {
      try {
        const connecting = connect(endpoint, { target: debugTarget }).then(connected => {
          if (exited || finishing) { connected.close(); throw new Error('The app exited before debug attachment'); }
          return connected;
        });
        client = await Promise.race([connecting, timedOut, ended.then(() => { throw launchError || new Error('The app exited before its renderer debug endpoint was ready; close other copies before retrying'); })]);
      } catch (error) {
        lastError = error;
        if (exited || finishing || ['ENG_DEBUG_AMBIGUOUS_TARGET', 'ENG_DEBUG_STARTUP_TIMEOUT'].includes(error.code)) throw error;
        await Promise.race([new Promise(resolve => setTimeout(resolve, Math.max(0, Math.min(200, deadline - Date.now())))), ended]);
      }
    }
    if (!client) throw launchError || new Error(`Renderer debug startup failed: ${lastError?.message || 'no endpoint appeared'}. The app may ignore debug launch options or hand off to an existing instance`);
    clearTimeout(startupTimer);
    onNote({ method: 'renderer-cdp', loaded: true, mainProcess: false, launched: true, endpoint });
    fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'debug-launch', endpoint, managed: true }) + '\n');
    return await observe(endpoint, { ...options, target: debugTarget, duration, log, connect: async () => client });
  } finally {
    finishing = true;
    clearTimeout(startupTimer);
    process.removeListener('SIGINT', stop);
    client?.close();
    if (!exited) {
      child.kill();
      let timer;
      await Promise.race([ended, new Promise(resolve => { timer = setTimeout(resolve, 2000); })]);
      clearTimeout(timer);
    }
    fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'debug-launch-exit', managed: true, closed: exited }) + '\n');
  }
}
