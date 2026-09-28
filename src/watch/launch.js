// Launches the app under test with the observation hook loaded into its main process, and waits for it to close.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { createRequire } from 'node:module';

const HOOK = path.join(import.meta.dirname, 'hook.cjs');
const exists = (file) => {
  try {
    fs.accessSync(file);
    return true;
  } catch {
    return false;
  }
};

/**
 * How to start the app: a project folder is run with its own Electron (node_modules/electron), a packaged app by its
 * executable. Also returns the code to scan statically: the folder, or the resources/app.asar of a packaged app.
 * @returns {{ command, args, staticInput }}
 */
export function resolveApp(target, extraArgs = []) {
  const resolved = path.resolve(target);
  if (!exists(resolved)) throw new Error(`${target} does not exist`);
  const stat = fs.statSync(resolved);

  if (stat.isDirectory() && resolved.endsWith('.app')) { // macOS bundle
    const macos = path.join(resolved, 'Contents', 'MacOS');
    const executable = fs.readdirSync(macos).find(name => !name.startsWith('.'));
    const asar = path.join(resolved, 'Contents', 'Resources', 'app.asar');
    return { command: path.join(macos, executable), args: extraArgs, staticInput: exists(asar) ? asar : undefined, packaged: true };
  }
  if (stat.isDirectory()) {
    if (!exists(path.join(resolved, 'package.json'))) throw new Error(`${target} has no package.json: pass the app folder or its packaged executable`);
    let electron;
    try {
      electron = createRequire(path.join(resolved, 'package.json'))('electron');
    } catch {
      throw new Error(`Electron is not installed in ${target}: run npm install there, or pass the packaged executable`);
    }
    // a development folder runs the shared Electron binary, whose fuses are not the app's: no binary fuse reading
    return { command: electron, args: [resolved, ...extraArgs], staticInput: resolved, packaged: false };
  }
  const resources = path.join(path.dirname(resolved), 'resources');
  const asar = path.join(resources, 'app.asar');
  const unpacked = path.join(resources, 'app');
  return { command: resolved, args: extraArgs, staticInput: exists(asar) ? asar : exists(unpacked) ? unpacked : undefined, packaged: true };
}

/**
 * Starts the app with the hook and resolves with the path of the log once the app has exited.
 * The user drives the app; Ctrl+C in the terminal closes it too.
 *
 * A project folder run with its own Electron loads the hook through NODE_OPTIONS=--require. Packaged apps ignore
 * NODE_OPTIONS (Electron drops most of its options there), so a packaged app is started paused under the Node inspector
 * (--inspect-brk, on a local port), the hook is loaded through it before any of the app's code runs, and the app is
 * resumed. That needs the EnableNodeCliInspectArguments fuse, on unless the build switched it off.
 */
export function watchApp(target, { args = [], marker, capture = true, log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-watch-')), 'session.jsonl'), stdio = 'inherit', onNote = () => {} } = {}) {
  const { command, args: commandArgs, packaged } = resolveApp(target, args);
  fs.writeFileSync(log, '');
  const quotedHook = HOOK.includes(' ') ? `"${HOOK}"` : HOOK;
  const env = {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + ' ' : ''}--require ${quotedHook}`,
    ELECTRONEGATIVITY_WATCH_LOG: log,
  };
  if (marker) env.ELECTRONEGATIVITY_WATCH_MARKER = String(marker);
  // download the front-end code pages run, for the static scan (capture/ next to the log)
  if (capture) env.ELECTRONEGATIVITY_WATCH_CAPTURE = '1';
  return (async () => {
    let port;
    if (packaged) {
      // packaged apps drop NODE_OPTIONS=--require: don't pass it, it only makes Electron print an error
      if (process.env.NODE_OPTIONS) env.NODE_OPTIONS = process.env.NODE_OPTIONS;
      else delete env.NODE_OPTIONS;
      port = await freePort();
    }
    const finalArgs = packaged ? [`--inspect-brk=127.0.0.1:${port}`, ...commandArgs] : commandArgs;
    return new Promise((resolve, reject) => {
      const child = spawn(command, finalArgs, { env, stdio });
      const stop = () => child.kill();
      process.once('SIGINT', stop);
      let exited = false;
      child.once('error', (error) => {
        exited = true;
        process.removeListener('SIGINT', stop);
        reject(error);
      });
      child.once('exit', () => {
        exited = true;
        process.removeListener('SIGINT', stop);
        resolve(log);
      });
      if (packaged) {
        loadThroughInspector(port, () => exited).then(result => onNote(result)).catch(error => {
          fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'hook-error', message: `inspector: ${error.message}` }) + '\n');
          onNote({ loaded: false, error: error.message });
        });
      }
    });
  })();
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/**
 * Connects to the paused app's inspector, loads the hook into its main process, and lets the app start. If the
 * inspector never comes up (the EnableNodeCliInspectArguments fuse is off), the app runs normally and nothing is
 * observed. The inspector closes once the hook is in.
 */
async function loadThroughInspector(port, hasExited, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let target;
  while (!target && Date.now() < deadline && !hasExited()) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1000) });
      const targets = await response.json();
      target = targets.find(t => t.webSocketDebuggerUrl);
    } catch {
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
  if (!target) throw new Error(hasExited() ? 'the app exited before its inspector could be reached' : 'the app\'s inspector did not answer (is the EnableNodeCliInspectArguments fuse off?)');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('could not connect to the app\'s inspector')), { once: true });
  });
  let id = 0;
  const pending = new Map();
  let paused;
  const pausedOnce = new Promise(resolve => { paused = resolve; });
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    if (message.id && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    } else if (message.method === 'Debugger.paused') paused();
  });
  const send = (method, params = {}) => new Promise((resolve) => {
    const messageId = ++id;
    pending.set(messageId, resolve);
    socket.send(JSON.stringify({ id: messageId, method, params }));
  });
  await send('Runtime.enable');
  await send('Debugger.enable');
  await send('Runtime.runIfWaitingForDebugger');
  // --inspect-brk stops on the first line of the app's JavaScript: load the hook there, before the app runs
  await Promise.race([pausedOnce, new Promise(resolve => setTimeout(resolve, 5000))]);
  const expression = `(() => {
    const load = typeof process.getBuiltinModule === 'function' ? process.getBuiltinModule('module').createRequire(${JSON.stringify(HOOK)}) : require;
    load(${JSON.stringify(HOOK)});
    // close the inspector once this session has disconnected, so the port doesn't stay open
    setTimeout(() => { try { (typeof process.getBuiltinModule === 'function' ? process.getBuiltinModule('inspector') : require('inspector')).close(); } catch {} }, 2000);
    return 'loaded';
  })()`;
  const result = await send('Runtime.evaluate', { expression, includeCommandLineAPI: true, returnByValue: true });
  await send('Debugger.resume');
  socket.close();
  const error = result.error || (result.result && result.result.exceptionDetails);
  if (error) throw new Error(`loading the hook failed: ${JSON.stringify(error).slice(0, 300)}`);
  return { loaded: true };
}
