'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');

const deadline = (work, ms = 4000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('timeout')), ms);
  Promise.resolve(work).then(v => { clearTimeout(timer); resolve(v); }, e => { clearTimeout(timer); reject(e); });
});
function createProofs(electron, write, { enabled = false, profile = {}, ipc, late = false } = {}) {
  const context = new AsyncLocalStorage();
  const sessions = new Map(), windows = new Map(), handlers = new Map();
  const toolContents = new Set();
  let creatingTool = false;
  const salt = crypto.randomBytes(32);
  const digest = value => crypto.createHmac('sha256', salt).update(String(value)).digest('hex');
  const record = (test, outcome, data = {}) => write('proof', { test, outcome, ...data });
  const guard = () => context.getStore();
  const deny = operation => { if (guard()) { record('side-effect', 'blocked', { operation, scope: guard().scope }); throw new Error('ENG_PROOF_SIDE_EFFECT_BLOCKED'); } };
  const run = (scope, fn) => context.run({ scope }, fn);
  const originals = [];
  // Async context follows timers/promises even after a probe times out. Bounded
  // callback probes cannot invoke common process, filesystem mutation or OS APIs.
  if (enabled || ipc) {
    const cp = require('node:child_process');
    const mutators = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'rename', 'renameSync',
      'mkdir', 'mkdirSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'truncate', 'truncateSync', 'chmod', 'chmodSync', 'chown', 'chownSync', 'link', 'linkSync', 'symlink', 'symlinkSync', 'createWriteStream', 'write', 'writeSync', 'writev', 'writevSync'];
    const wrap = (obj, name, check = () => true) => {
      const original = obj[name]; if (typeof original !== 'function') return;
      obj[name] = function (...args) { if (check(args)) deny(name); return original.apply(this, args); };
      originals.push([obj, name, original]);
    };
    for (const name of ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']) wrap(cp, name);
    for (const name of mutators) { wrap(fs, name); wrap(fs.promises, name); }
    const writable = args => typeof args[1] === 'number' ? (args[1] & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND)) !== 0 : /[wa+]/.test(String(args[1] || 'r'));
    for (const name of ['open', 'openSync']) wrap(fs, name, writable);
    wrap(fs.promises, 'open', writable);
    for (const name of ['trashItem', 'beep']) wrap(electron.shell, name);
    require('node:module').syncBuiltinESMExports();
  }
  function registerSession(ses, label) { if (!sessions.has(ses)) sessions.set(ses, { label, request: null, check: null }); return sessions.get(ses); }
  function registerContents(contents) {
    if (creatingTool) { toolContents.add(contents.id); write('proof-window', { id: contents.id }); }
    windows.set(contents.id, { contents, open: null });
    for (const name of ['loadURL', 'loadFile', 'reload', 'reloadIgnoringCache', 'downloadURL', 'print', 'printToPDF']) {
      if (typeof contents[name] !== 'function') continue;
      const original = contents[name];
      contents[name] = function (...args) { deny(`webContents.${name}`); return original.apply(this, args); };
    }
    contents.once('destroyed', () => windows.delete(contents.id));
    if (guard()) { toolContents.add(contents.id); setImmediate(() => { if (!contents.isDestroyed()) contents.close(); }); }
    if (enabled) {
      let pending = false, lastKey;
      const probe = () => {
        if (pending || toolContents.has(contents.id) || contents.isDestroyed() || contents.getType() !== 'window') return;
        const state = windows.get(contents.id), ses = sessions.get(contents.session);
        const key = [contents.getURL(), state?.open, ses?.request, ses?.check, contents.listeners('will-navigate').length];
        if (lastKey && key.every((v, i) => v === lastKey[i])) return;
        lastKey = key; pending = true;
        setTimeout(() => proveContents(contents).catch(() => record('handlers', 'error', { id: contents.id })).finally(() => { pending = false; }), 750).unref();
      };
      contents.on('did-finish-load', probe);
      const timer = setInterval(probe, 3000); timer.unref(); contents.once('destroyed', () => clearInterval(timer));
    }
  }
  const setOpen = (contents, handler) => { const s = windows.get(contents.id); if (s) s.open = handler; };
  const setPermission = (ses, type, handler) => { registerSession(ses)[type] = handler; };
  const registerIpc = (channel, listener, once = false) => handlers.set(channel, { listener, once });
  async function proveContents(contents) {
    if (contents.isDestroyed()) return;
    if (late) { record('handlers', 'skipped', { id: contents.id, reason: 'late hook cannot guarantee callback guard coverage', scope: 'handler-decision' }); return; }
    const state = windows.get(contents.id), ses = sessions.get(contents.session);
    for (const origin of profile.origins || ['https://eng-proof.invalid']) {
      const url = `${origin}/electronegativity-proof`;
      const base = { id: contents.id, url, scope: 'handler-decision', synthetic: true };
      try {
        let prevented = false;
        const event = { url, isMainFrame: true, frame: contents.mainFrame, initiator: contents.mainFrame,
          sender: contents, get defaultPrevented() { return prevented; }, preventDefault() { prevented = true; } };
        const listeners = contents.rawListeners('will-navigate').filter(l => !l.engObserver);
        // Do not consume once listeners or manufacture decisions from incomplete late instrumentation.
        if (late || listeners.some(l => l.listener)) record('navigation', 'inconclusive', { ...base, reason: 'late hook or once listener' });
        else {
          await run('navigation', () => deadline(Promise.all(listeners.map(l => l.call(contents, event, url)))));
          record('navigation', prevented ? 'blocked' : 'allowed', { ...base, handlers: listeners.length });
        }
      } catch (e) { record('navigation', e.message === 'timeout' ? 'timeout' : 'inconclusive', base); }
      try {
        if (late && !state?.open) record('window-open', 'inconclusive', { ...base, reason: 'late hook' });
        else {
          const result = state?.open ? await run('window-open', () => deadline(state.open({ url, frameName: '', features: '', disposition: 'new-window', referrer: { url: '', policy: 'no-referrer' } }))) : { action: 'allow' };
          record('window-open', result?.action === 'deny' ? 'blocked' : result?.action === 'allow' ? 'allowed' : 'inconclusive', { ...base, handlers: state?.open ? 1 : 0 });
        }
      } catch { record('window-open', 'inconclusive', base); }
      const details = { requestingUrl: url, embeddingOrigin: origin, securityOrigin: origin, isMainFrame: true, mediaTypes: ['video'], mediaType: 'video' };
      // A real webContents is supplied, so callbacks that inspect getURL() see its
      // real origin. Record the mismatch explicitly instead of pretending to be a foreign renderer.
      const permissionBase = { ...base, actualSender: safeUrl(contents.getURL()), permission: 'media', media: 'camera' };
      if (!ses?.request) record('permission-request', late ? 'inconclusive' : 'not-configured', permissionBase);
      else try {
        const granted = await run('permission-request', () => deadline(new Promise(resolve => ses.request(contents, 'media', resolve, details))));
        record('permission-request', granted === true ? 'allowed' : granted === false ? 'blocked' : 'inconclusive', permissionBase);
      } catch (e) { record('permission-request', e.message === 'timeout' ? 'timeout' : 'inconclusive', permissionBase); }
      if (!ses?.check) record('permission-check', late ? 'inconclusive' : 'not-configured', permissionBase);
      else try {
        const granted = await run('permission-check', () => deadline(ses.check(contents, 'media', origin, details)));
        record('permission-check', granted === true ? 'allowed' : granted === false ? 'blocked' : 'inconclusive', permissionBase);
      } catch { record('permission-check', 'inconclusive', permissionBase); }
    }
  }
  async function certificate(ses, label) {
    const nonce = crypto.randomBytes(16).toString('hex');
    let server, window;
    try {
      server = https.createServer({ key: fs.readFileSync(path.join(__dirname, 'fixtures/localhost-key.pem')), cert: fs.readFileSync(path.join(__dirname, 'fixtures/localhost-cert.pem')) }, (req, res) => {
        if (req.url !== `/${nonce}`) { res.writeHead(404); res.end(); return; }
        res.setHeader('Content-Type', 'text/plain'); res.setHeader('Content-Security-Policy', "default-src 'none'"); res.end(nonce);
      });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
      write('proof-listener', { pid: process.pid, port: server.address().port, purpose: 'certificate' });
      const url = `https://127.0.0.1:${server.address().port}/${nonce}`;
      const outcome = await sessionRequest(electron, ses, url, nonce);
      record('certificate', outcome, { session: label, scope: 'session-network', selfSigned: true, cookieFree: true });
      // Chromium navigation additionally exercises app certificate-error handlers,
      // which a session net.request does not necessarily call.
      try {
        creatingTool = true;
        window = new electron.BrowserWindow({ show: false, webPreferences: { session: ses, nodeIntegration: false, contextIsolation: true, sandbox: true } });
      } finally { creatingTool = false; }
      toolContents.add(window.webContents.id);
      try {
        await deadline(window.loadURL(url), 5000);
        const body = await deadline(window.webContents.executeJavaScript('document.body.innerText', false));
        record('certificate', body.trim() === nonce ? 'accepted' : 'inconclusive', { session: label, scope: 'chromium-navigation', selfSigned: true, toolWindow: true });
      } catch (e) { record('certificate', /CERT|SSL/i.test(e.message) ? 'blocked' : e.message === 'timeout' ? 'timeout' : 'inconclusive', { session: label, scope: 'chromium-navigation', selfSigned: true, toolWindow: true }); }
    } catch { record('certificate', 'inconclusive', { session: label, scope: 'session-network' }); }
    finally { if (window && !window.isDestroyed()) window.destroy(); if (server) { server.closeAllConnections(); server.close(); } }
  }
  const certificateSessions = new WeakSet();
  function queueCertificate(ses, label) {
    if (!enabled || certificateSessions.has(ses)) return;
    certificateSessions.add(ses);
    setTimeout(() => { void certificate(ses, label); }, 1200).unref();
  }
  async function linkTests() {
    for (const link of profile.links || []) {
      const candidates = [...windows.values()].map(w => w.contents).filter(c => !toolContents.has(c.id) && c.getURL().startsWith(link.page));
      if (candidates.length !== 1) { record('external-scheme', 'inconclusive', { reason: 'page selection is not unique' }); continue; }
      for (const url of ['file:///C:/eng-proof-does-not-exist.txt', 'eng-proof-unregistered:harmless']) {
        const method = JSON.stringify(link.method), arg = JSON.stringify(url);
        try {
          // Renderer execution propagates to main IPC independently of Node async
          // context. A dedicated window ID guard is checked by the IPC wrapper.
          linkSender = candidates[0].id;
          const script = `(async()=>{let owner=window;const parts=${method}.split('.');for(const p of parts.slice(0,-1))owner=owner?.[p];const fn=owner?.[parts.at(-1)];if(typeof fn!=='function')return false;await fn.call(owner,${arg});return true;})()`;
          await deadline(candidates[0].executeJavaScript(script, false));
          record('external-scheme', 'invoked', { id: candidates[0].id, scheme: new URL(url).protocol, scope: 'configured-link-route' });
        } catch { record('external-scheme', 'inconclusive', { scope: 'configured-link-route' }); }
        finally { linkSender = undefined; }
      }
    }
  }
  let linkSender, ipcSender;
  function invoke(event, channel, listener, args) {
    const proof = event.sender?.id === ipcSender || event.sender?.id === linkSender;
    if (proof) return run('ipc-read-only', () => listener(event, ...args));
    return listener(event, ...args);
  }
  async function ipcTests() {
    if (!ipc) return;
    if (late) { record('ipc', 'skipped', { reason: 'IPC requires instrumentation before application startup' }); return; }
    let server, window, dir;
    try {
      dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'eng-ipc-proof-'));
      fs.mkdirSync(path.join(dir, 'inside'));
      const token = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(path.join(dir, 'canary.txt'), token);
      const canary = path.join(dir, 'inside', '..', 'canary.txt');
      server = http.createServer((req, res) => { res.setHeader('Content-Security-Policy', "default-src 'none'"); res.end('<!doctype html><title>Electronegativity foreign sender</title>'); });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
      write('proof-listener', { pid: process.pid, port: server.address().port, purpose: 'foreign-renderer' });
      try {
        creatingTool = true;
        window = new electron.BrowserWindow({ show: false, webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true,
          partition: `eng-proof-${crypto.randomBytes(8).toString('hex')}`, preload: path.join(__dirname, 'proof-preload.cjs') } });
      } finally { creatingTool = false; }
      toolContents.add(window.webContents.id); ipcSender = window.webContents.id;
      const origin = `http://127.0.0.1:${server.address().port}`;
      await deadline(window.loadURL(origin));
      for (const h of ipc.handlers) {
        const registered = handlers.get(h.channel);
        if (!registered || registered.once || /child_process|\b(?:exec|spawn|fork)\s*\(/.test(String(registered.listener))) {
          record('ipc', 'skipped', { channel: h.channel, reason: 'missing, once or command-capable handler' }); continue;
        }
        const args = JSON.parse(JSON.stringify(h.args).replaceAll('$CANARY_PATH', canary.replace(/\\/g, '\\\\')));
        try {
          const script = `window.engProof.invoke(${JSON.stringify(h.channel)},${JSON.stringify(args)})`;
          const result = await deadline(window.webContents.executeJavaScript(script, false));
          const canaryRead = typeof result === 'string' ? result.includes(token) : Buffer.isBuffer(result) ? result.includes(Buffer.from(token)) :
            result instanceof Uint8Array ? Buffer.from(result).includes(Buffer.from(token)) : JSON.stringify(result)?.includes(token) === true;
          record('ipc', canaryRead ? 'canary-read' : 'resolved', { channel: h.channel, scope: 'foreign-sender', sender: origin, contract: h.contract,
            toolBridge: true, traversal: h.contract === 'file-read', resultType: typeof result });
        } catch (e) { record('ipc', e.message === 'timeout' ? 'timeout' : 'rejected', { channel: h.channel, scope: 'foreign-sender', toolBridge: true }); }
      }
    } catch { record('ipc', 'inconclusive', { scope: 'foreign-sender' }); }
    finally {
      ipcSender = undefined; if (window && !window.isDestroyed()) window.destroy();
      if (server) { server.closeAllConnections(); server.close(); } if (dir) fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  let snapshotBusy = false;
  async function logoutSnapshot(phase) {
    if (snapshotBusy || !['before', 'after'].includes(phase)) return;
    snapshotBusy = true;
    const entries = [], errors = [];
    try {
      for (const [ses, s] of sessions) {
        try {
          const cookies = await deadline(ses.cookies.get({}));
          for (const c of cookies.slice(0, 5000)) entries.push({ store: 'cookies', key: digest(`${s.label}:${c.domain}:${c.path}:${c.name}`), value: digest(c.value), candidate: /token|auth|session|credential|password/i.test(c.name) });
          if (cookies.length > 5000) errors.push('cookie-limit');
        } catch { errors.push('cookies-unreadable'); }
      }
      for (const { contents } of windows.values()) {
        if (toolContents.has(contents.id) || contents.isDestroyed()) continue;
        try {
          const values = await deadline(contents.executeJavaScript(`(()=>{const rows=[];for(const name of ['localStorage','sessionStorage']){try{const s=window[name];for(let i=0;i<Math.min(s.length,1000);i++){const k=s.key(i);const v=s.getItem(k);rows.push({store:name,key:k,value:v?.slice(0,65536),limited:v?.length>65536});}if(s.length>1000)rows.push({error:'storage-limit'});}catch{rows.push({error:'storage-unreadable'});}}return rows;})()`, false));
          for (const v of values) {
            if (v.error || v.limited) { errors.push(v.error || 'value-limit'); continue; }
            const url = new URL(contents.getURL());
            const origin = url.origin === 'null' ? url.href.split(/[?#]/)[0] : url.origin;
            const owner = v.store === 'sessionStorage' ? contents.id : sessions.get(contents.session)?.label;
            entries.push({ store: v.store, key: digest(`${owner}:${origin}:${v.store}:${v.key}`), value: digest(v.value), candidate: /token|auth|session|credential|password/i.test(v.key) });
          }
        } catch { errors.push('renderer-storage-unreadable'); }
      }
      write('logout-snapshot', { phase, entries, errors: [...new Set(errors)], scope: 'cookies-and-web-storage' });
    } finally { snapshotBusy = false; }
  }
  const start = async () => { if (enabled) await linkTests(); await ipcTests(); };
  return { registerSession, registerContents, setOpen, setPermission, registerIpc, invoke, guard, deny, run, queueCertificate,
    logoutSnapshot, start, proveContents, toolContents, originals, isToolCreation: () => creatingTool };
}

function sessionRequest(electron, ses, url, nonce) {
  return new Promise(resolve => {
    const req = electron.net.request({ url, session: ses, useSessionCookies: false, credentials: 'omit' });
    let finished = false;
    const done = outcome => { if (finished) return; finished = true; clearTimeout(timer); req.abort(); resolve(outcome); };
    const timer = setTimeout(() => done('timeout'), 5000);
    req.on('redirect', () => done('inconclusive'));
    req.on('error', error => done(/CERT|SSL/i.test(error.message) ? 'blocked' : 'inconclusive'));
    req.on('response', response => {
      let body = '';
      response.on('data', b => { body += b; if (body.length > 1024) done('inconclusive'); });
      response.on('end', () => done(response.statusCode === 200 && body === nonce ? 'accepted' : 'inconclusive'));
    });
    req.end();
  });
}
function safeUrl(url) { try { const u = new URL(url); u.search = ''; u.hash = ''; u.username = ''; u.password = ''; return u.href; } catch { return ''; } }
module.exports = { createProofs, deadline, sessionRequest };
