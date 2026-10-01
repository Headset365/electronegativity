// Launches the app under test with the observation hook loaded into its main process, and waits for it to close.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { createRequire } from 'node:module';

const HOOK = path.join(import.meta.dirname, 'hook.cjs');
// how long an app that has quit gets to end its process before it is closed
const QUIT_GRACE_MS = 15000;
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
export function watchApp(target, { args = [], marker, active = false, campaign = false, capture = true, traffic = true, scope = [], reveal = false, screenshots, commands, remoteHosts = [], headerNames = [], headersFile, log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-watch-')), 'session.jsonl'), stdio = 'inherit', onNote = () => {} } = {}) {
  const { command, args: commandArgs, packaged, staticInput } = resolveApp(target, args);
  fs.writeFileSync(log, '');
  const quotedHook = HOOK.includes(' ') ? `"${HOOK}"` : HOOK;
  const env = {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + ' ' : ''}--require ${quotedHook}`,
    ELECTRONEGATIVITY_WATCH_LOG: log,
  };
  if (marker) env.ELECTRONEGATIVITY_WATCH_MARKER = String(marker);
  if (active) env.ELECTRONEGATIVITY_WATCH_ACTIVE = '1';
  if (campaign) env.ELECTRONEGATIVITY_WATCH_CAMPAIGN = '1';
  // the file the CLI writes send-marker commands to, for the hook to re-send the marker request through the app's session
  if (commands) env.ELECTRONEGATIVITY_WATCH_COMMANDS = commands;
  // download the front-end code pages run, for the static scan (capture/ next to the log)
  if (capture) env.ELECTRONEGATIVITY_WATCH_CAPTURE = '1';
  // the passive traffic checks run inside the app (--no-watch-traffic turns them off); scope: the app's own domains
  env.ELECTRONEGATIVITY_WATCH_TRAFFIC = traffic ? '1' : '0';
  if (scope.length > 0) env.ELECTRONEGATIVITY_WATCH_SCOPE = scope.join(',');
  // --show-secrets: findings keep the full values
  if (reveal) env.ELECTRONEGATIVITY_WATCH_REVEAL = '1';
  // evidence screenshots (--watch-screenshots): only when asked, pages can show confidential data
  if (screenshots) env.ELECTRONEGATIVITY_WATCH_SCREENSHOTS = path.resolve(screenshots);
  // --remote: the only hosts the hook downloads from; --remote-header names: copied from the app's requests to them
  if (remoteHosts.length > 0) env.ELECTRONEGATIVITY_WATCH_REMOTE_HOSTS = remoteHosts.join(',');
  if (remoteHosts.length > 0 && headerNames.length > 0 && headersFile) {
    env.ELECTRONEGATIVITY_WATCH_HEADER_NAMES = headerNames.join(',');
    env.ELECTRONEGATIVITY_WATCH_HEADERS_FILE = headersFile;
  }
  return (async () => {
    let port;
    if (packaged) {
      // packaged apps drop NODE_OPTIONS=--require: don't pass it, it only makes Electron print an error
      if (process.env.NODE_OPTIONS) env.NODE_OPTIONS = process.env.NODE_OPTIONS;
      else delete env.NODE_OPTIONS;
      port = await freePort();
    }
    // --inspect-brk-node pauses inside Electron's own startup. (--inspect-brk pauses at the app's first line, but some
    // Electron releases, 34 among them, crash on that path: "ReferenceError: resolvedArgv is not defined".)
    const finalArgs = packaged ? [`--inspect-brk-node=127.0.0.1:${port}`, ...commandArgs] : commandArgs;
    return new Promise((resolve, reject) => {
      const child = spawn(command, finalArgs, { env, stdio });
      const stop = () => child.kill();
      process.once('SIGINT', stop);
      let exited = false;
      // An app that has quit (the observer recorded it) but whose process stays alive, e.g. held open by a dialog the
      // operating system showed for a link or file it was handed, would keep the session waiting for good: after a grace
      // period it is closed, and the log says so.
      let quitSeen = false;
      let lingerTimer;
      let logOffset = 0;
      const quitWatch = setInterval(() => {
        if (quitSeen || exited) return;
        try {
          const size = fs.statSync(log).size;
          if (size <= logOffset) return;
          const fd = fs.openSync(log, 'r');
          try {
            const buffer = Buffer.alloc(size - logOffset);
            fs.readSync(fd, buffer, 0, buffer.length, logOffset);
            logOffset = size;
            if (!buffer.toString('utf8').includes('"kind":"quit"')) return;
          } finally {
            fs.closeSync(fd);
          }
        } catch {
          return;
        }
        quitSeen = true;
        lingerTimer = setTimeout(() => {
          if (exited) return;
          try {
            fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'hook-error', message: `the app quit but its process was still running ${QUIT_GRACE_MS / 1000} s later: it was closed` }) + '\n');
          } catch {
            // best effort
          }
          onNote({ lingered: true });
          child.kill();
        }, QUIT_GRACE_MS);
      }, 1000);
      const done = () => {
        exited = true;
        clearInterval(quitWatch);
        clearTimeout(lingerTimer);
        process.removeListener('SIGINT', stop);
      };
      child.once('error', (error) => {
        done();
        reject(error);
      });
      child.once('exit', () => {
        done();
        resolve(log);
      });
      if (packaged) {
        loadThroughInspector(port, () => exited, mainScriptOf(staticInput), 30000, inspectorTrace(log)).then(result => onNote(result)).catch(error => {
          fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'hook-error', message: `inspector: ${error.message}` }) + '\n');
          onNote({ loaded: false, error: error.message });
        });
      }
    });
  })();
}

// The steps of loading the observer through the inspector, in the session log (and on stderr with
// ELECTRONEGATIVITY_TRACE=1), so a session that could not be observed says where it stopped
function inspectorTrace(log) {
  const started = Date.now();
  return (step) => {
    try {
      fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind: 'inspector-step', step }) + '\n');
    } catch {
      // best effort
    }
    if (process.env.ELECTRONEGATIVITY_TRACE === '1') process.stderr.write(`[inspector +${Date.now() - started}ms] ${step}\n`);
  };
}

export function freePort() {
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

/** The app's package.json, from its code (a folder or an app.asar), or undefined. */
export function readManifest(code) {
  try {
    const text = /\.asar$/i.test(code || '') ? createRequire(import.meta.url)('@electron/asar').extractFile(code, 'package.json').toString('utf8')
      : fs.readFileSync(path.join(code, 'package.json'), 'utf8');
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// The app's entry script, from its package.json "main" (index.js by default), relative to its code
export function mainScriptOf(code) {
  const manifest = readManifest(code);
  if (!manifest) return undefined;
  let main = typeof manifest.main === 'string' && manifest.main.trim() ? manifest.main.trim() : 'index.js';
  main = main.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!/\.[cm]?js$/i.test(main)) main += '.js';
  return main;
}

// Script URLs as the inspector reports them: file:///C:/Program%20Files/App/resources/app.asar/main.js, or a path
const scriptUrlPattern = (main) => {
  const tail = main.split('/').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '(?: |%20)')).join('[\\\\/]');
  return `[\\\\/]app(?:\\.asar)?[\\\\/]${tail}$`;
};

/**
 * Connects to the paused app's inspector and loads the hook into its main process before any of the app's code runs:
 * the app is started paused inside Electron's startup (--inspect-brk-node), a breakpoint is set on the first line of
 * its entry script, and the hook is loaded when it is reached. If the inspector never comes up (the
 * EnableNodeCliInspectArguments fuse is off), the app runs normally and nothing is observed. The inspector closes once
 * the hook is in.
 */
async function loadThroughInspector(port, hasExited, mainScript, timeoutMs = 30000, trace = () => {}) {
  const deadline = Date.now() + timeoutMs;
  let target;
  trace(`waiting for the inspector on 127.0.0.1:${port}`);
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
  trace('inspector target found');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the app\'s inspector did not accept a connection')), 10000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('could not connect to the app\'s inspector')); }, { once: true });
  });
  trace('connected');
  let id = 0;
  let closed = false;
  const pending = new Map();
  const pauses = [];
  let wake = () => {};
  socket.addEventListener('message', (event) => {
    let message;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      return;
    }
    if (message.id && pending.has(message.id)) {
      pending.get(message.id).resolve(message);
      pending.delete(message.id);
    } else if (message.method === 'Debugger.paused') {
      pauses.push(message.params || {});
      wake();
    }
  });
  // a closed connection (the app exited, or closed its inspector) fails what is still waiting for an answer
  socket.addEventListener('close', () => {
    closed = true;
    for (const { reject } of pending.values()) reject(new Error('the app\'s inspector closed the connection'));
    pending.clear();
    wake();
  });
  // every command gets an answer or an error: a command left unanswered must not leave the app paused for good
  const send = (method, params = {}, ms = 10000) => new Promise((resolve, reject) => {
    if (closed) return reject(new Error(`${method}: the app's inspector closed the connection`));
    const messageId = ++id;
    const timer = setTimeout(() => { pending.delete(messageId); reject(new Error(`${method} got no answer from the app's inspector`)); }, ms);
    pending.set(messageId, { resolve: (message) => { clearTimeout(timer); resolve(message); }, reject: (error) => { clearTimeout(timer); reject(error); } });
    try {
      socket.send(JSON.stringify({ id: messageId, method, params }));
    } catch (error) {
      clearTimeout(timer);
      pending.delete(messageId);
      reject(error);
    }
  });
  const nextPause = (ms) => pauses.length ? Promise.resolve(pauses.shift()) : new Promise(resolve => {
    const timer = setTimeout(() => { wake = () => {}; resolve(undefined); }, ms);
    wake = () => {
      if (!pauses.length && !closed) return;
      clearTimeout(timer);
      wake = () => {};
      resolve(pauses.shift());
    };
  });

  const breakpoints = [];
  // Electron's patch to Node's module loader passes process._firstFileName to the --inspect-brk path when the app's
  // entry script is compiled, and some releases (34 among them) assign it to a variable the loader no longer declares:
  // "ReferenceError: resolvedArgv is not defined", before any of the app's code runs, and the app can't start. The value
  // only tells the inspector where to pause, which the entry breakpoint does. At the first pause, before `process`
  // exists, an inherited accessor that ignores writes keeps it unset; it is removed once the hook is in.
  const guard = `(() => {
    Object.defineProperty(Object.prototype, '_firstFileName', { get() { return undefined; }, set() {}, configurable: true, enumerable: false });
    return true;
  })()`;
  const hookExpression = `(() => {
    if (typeof process !== 'object' || !process || typeof process.cwd !== 'function') return 'not ready';
    delete Object.prototype._firstFileName;
    const load = typeof process.getBuiltinModule === 'function' ? process.getBuiltinModule('module').createRequire(${JSON.stringify(HOOK)}) : require;
    load(${JSON.stringify(HOOK)});
    // close the inspector once this session has disconnected, so the port doesn't stay open
    setTimeout(() => { try { (typeof process.getBuiltinModule === 'function' ? process.getBuiltinModule('inspector') : require('inspector')).close(); } catch {} }, 2000);
    return 'loaded';
  })()`;
  const valueOf = (answer) => answer && answer.result && answer.result.result && answer.result.result.value;
  const failureOf = (answer) => answer && (answer.error || (answer.result && answer.result.exceptionDetails));
  let atEntry = false;
  let loaded = false;
  let failure;
  try {
    await send('Runtime.enable');
    await send('Debugger.enable');
    trace('debugger enabled');
    if (mainScript) {
      const set = await send('Debugger.setBreakpointByUrl', { urlRegex: scriptUrlPattern(mainScript), lineNumber: 0 });
      if (set.result && set.result.breakpointId) breakpoints.push(set.result.breakpointId);
      trace(`entry breakpoint ${breakpoints.length ? 'set' : 'not set'} for ${mainScript}`);
    }
    await send('Runtime.runIfWaitingForDebugger');
    // the first pause is inside Electron's startup; load the hook at the first of our breakpoints that is reached
    let guarded = false;
    let pausesSeen = 0;
    for (let pause = await nextPause(10000); pause && Date.now() < deadline; pause = await nextPause(15000)) {
      pausesSeen++;
      if (!guarded) guarded = !!(await send('Runtime.evaluate', { expression: guard, returnByValue: true })).result;
      if ((pause.hitBreakpoints || []).some(hit => breakpoints.includes(hit))) {
        const answer = await send('Runtime.evaluate', { expression: hookExpression, includeCommandLineAPI: true, returnByValue: true });
        failure = failureOf(answer);
        if (valueOf(answer) === 'loaded') {
          atEntry = loaded = true;
          break;
        }
      }
      await send('Debugger.resume');
    }
    trace(`${pausesSeen} pause(s) seen, ${atEntry ? 'loaded at the entry breakpoint' : 'entry breakpoint not reached'}`);
    for (const breakpointId of breakpoints) await send('Debugger.removeBreakpoint', { breakpointId });
    breakpoints.length = 0;
    await send('Debugger.resume').catch(() => {});
    // no breakpoint reached (an entry script we couldn't find): load it now, late, once Node's process object exists
    for (let tries = 0; !loaded && tries < 20 && !closed && !hasExited(); tries++) {
      const answer = await send('Runtime.evaluate', { expression: hookExpression, includeCommandLineAPI: true, returnByValue: true });
      failure = failureOf(answer) || failure;
      if (valueOf(answer) === 'loaded') loaded = true;
      else if (failureOf(answer)) break;
      else await new Promise(resolve => setTimeout(resolve, 500));
    }
    trace(loaded ? 'hook loaded' : 'hook not loaded');
  } catch (error) {
    failure = failure || error.message;
    trace(`failed: ${error.message}`);
  } finally {
    // Whatever happened, the app must not stay paused: drop our breakpoints and let it run
    if (!closed) {
      for (const breakpointId of breakpoints) await send('Debugger.removeBreakpoint', { breakpointId }, 3000).catch(() => {});
      if (!loaded) await send('Runtime.evaluate', { expression: 'delete Object.prototype._firstFileName', returnByValue: true }, 3000).catch(() => {});
      await send('Runtime.runIfWaitingForDebugger', {}, 3000).catch(() => {});
      await send('Debugger.disable', {}, 3000).catch(() => {});
      await send('Debugger.resume', {}, 3000).catch(() => {});
    }
    try {
      socket.close();
    } catch {
      // already closed
    }
  }
  if (!loaded) throw new Error(`loading the hook failed: ${typeof failure === 'string' ? failure : JSON.stringify(failure || 'the app was never ready for it').slice(0, 300)}`);
  // not at a breakpoint: the app's code had already started when the hook loaded (it is marked late)
  return { loaded: true, atEntry };
}
