// Renderer-only attachment through the same local DevTools protocol endpoint used by Edge.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { normalizeCampaign, hostsOutsideScope } from './campaign.js';
import { followLog } from './assistant.js';
const require = createRequire(import.meta.url);
const { inspectBody, replayHeaders } = require('./capture.cjs');
const { hostAllowed, pickHeaders } = require('../remote/hosts.cjs');
const { fillMarkerBody } = require('./hook.cjs');
const { rendererObserver } = require('./renderer.cjs');
const { runCampaign, CASES, RESOURCES, startResourceReceiver } = require('./campaign.cjs');
const { createTrafficObserver } = require('./traffic_hook.cjs');

export function localDebugURL(value, protocol = 'http:') {
  const url = new URL(value);
  if (url.protocol !== protocol || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.search || url.hash) throw new Error('Debug endpoints must use a loopback address without credentials, query or fragment');
  return url;
}
const redact = value => {
  try { const url = new URL(value); url.username = ''; url.password = ''; url.search = ''; url.hash = ''; return url.href; }
  catch { return String(value || '').slice(0, 300); }
};

export async function connectDebug(endpoint, { target, fetchImpl = fetch, Socket = WebSocket, timeout = 10000 } = {}) {
  const base = localDebugURL(endpoint);
  const response = await fetchImpl(new URL('/json/list', base), { signal: AbortSignal.timeout(timeout), redirect: 'error' });
  if (!response.ok) throw new Error(`Debug target discovery failed: HTTP ${response.status}`);
  const list = await response.json();
  const pages = list.filter(item => item.type === 'page' && item.webSocketDebuggerUrl &&
    !/^(devtools:|chrome:|about:blank)/.test(item.url || '') && (!target || item.id === target || item.url?.startsWith(target)));
  if (pages.length !== 1) throw Object.assign(new Error(`Expected one renderer target, found ${pages.length}; use --debug-target with a target ID or URL prefix`),
    { code: pages.length > 1 ? 'ENG_DEBUG_AMBIGUOUS_TARGET' : 'ENG_DEBUG_NO_TARGET' });
  const selected = pages[0], ws = localDebugURL(selected.webSocketDebuggerUrl, 'ws:');
  if (ws.port !== base.port) throw new Error('The target WebSocket must use the same local port as its debug endpoint');
  const socket = new Socket(ws.href), events = new EventEmitter(), pending = new Map();
  let id = 0, closed = false;
  const fail = () => {
    if (closed) return;
    closed = true;
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('Debug connection closed')); }
    pending.clear(); events.emit('closed');
  };
  socket.addEventListener('close', fail);
  socket.addEventListener('error', fail);
  socket.addEventListener('message', event => {
    let message;
    try { message = JSON.parse(String(event.data)); } catch { return; }
    if (message.id && pending.has(message.id)) {
      const entry = pending.get(message.id); pending.delete(message.id); clearTimeout(entry.timer);
      if (message.error) entry.reject(new Error(`DevTools ${entry.method} failed: ${message.error.message}`));
      else entry.resolve(message.result || {});
    } else if (message.method) events.emit('protocol', message.method, message.params || {});
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new Error('Debug connection timed out')); }, timeout);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Could not connect to the renderer debugger')); }, { once: true });
    socket.addEventListener('close', () => { clearTimeout(timer); reject(new Error('Debug connection closed before opening')); }, { once: true });
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    if (closed) return reject(new Error('Debug connection closed'));
    const messageId = ++id;
    const timer = setTimeout(() => { pending.delete(messageId); reject(new Error(`DevTools ${method} timed out`)); }, timeout);
    pending.set(messageId, { resolve, reject, timer, method });
    try { socket.send(JSON.stringify({ id: messageId, method, params })); }
    catch (error) { clearTimeout(timer); pending.delete(messageId); reject(error); }
  });
  return { send, events, target: selected, close: () => { socket.close(); fail(); } };
}

export async function watchDebug(endpoint, { target, duration = 0, marker, active = false, campaign = false, scope = [], traffic = true,
  reveal = false, screenshots, log, commands, remoteHosts = [], headerNames = [], headersFile, connect = connectDebug } = {}) {
  if (!Number.isInteger(duration) || duration < 0 || duration > 86400) throw new Error('Debug duration must be 0–86400 seconds');
  const client = await connect(endpoint, { target });
  const id = client.target.id, key = `__eng_debug_${crypto.randomBytes(8).toString('hex')}`;
  let currentURL = client.target.url, running = false, stopped = false, replayId = 0, timer, durationTimer, stopCommands, scriptId;
  const requests = new Map(), replays = new Map(), extraHeaders = new Map(), headerPages = new Set(), tasks = new Set();
  const contexts = new Set();
  const controller = new AbortController();
  const write = (kind, data = {}) => fs.appendFileSync(log, JSON.stringify({ t: Date.now(), kind, ...data }) + '\n');
  // --remote-header names: the values the page sends to the --remote hosts, the latest per host, handed to the CLI in
  // `headersFile` (never the log). The ExtraInfo event carries the headers actually sent, cookies included.
  const copying = !!headersFile && remoteHosts.length > 0 && headerNames.length > 0;
  const copiedHeaders = {}, requestUrls = new Map(), sentHeaders = new Map();
  const copyHeaders = (url, headers) => {
    if (!/^https?:/i.test(url) || !hostAllowed(url, remoteHosts)) return;
    const host = new URL(url).hostname.toLowerCase();
    copiedHeaders[host] = { ...copiedHeaders[host], ...pickHeaders(headers, headerNames) };
  };
  // what the attachment sees of write requests, on stderr with ELECTRONEGATIVITY_TRACE=1 (no bodies or headers)
  const trace = (text) => { if (process.env.ELECTRONEGATIVITY_TRACE === '1') process.stderr.write(`[debug] ${text}\n`); };
  const task = promise => { tasks.add(promise); promise.catch(error => { if (!stopped) write('hook-error', { message: error.message }); }).finally(() => tasks.delete(promise)); };
  const evaluate = async expression => {
    const result = await client.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error('Renderer operation failed; check the selected page and its session');
    return result.result?.value;
  };
  const shot = async reason => {
    if (!screenshots) return;
    if (shot.count >= 25) return;
    shot.count = (shot.count || 0) + 1;
    fs.mkdirSync(screenshots, { recursive: true });
    const result = await client.send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(screenshots, `debug-${Date.now()}-${reason}.png`), Buffer.from(result.data, 'base64'));
  };
  const metadata = async () => {
    const page = await evaluate(`({ url: location.href, csp: document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.content || null })`);
    if (!page) return;
    currentURL = page.url;
    write('page', { id, type: 'renderer', url: redact(currentURL), prefs: {}, observer: 'cdp' });
    // A late attachment cannot infer a missing CSP header from a missing meta tag.
    if (page.csp || headerPages.has(redact(currentURL))) write('page-meta-csp', { id, url: redact(currentURL), csp: page.csp });
  };
  const dbg = new EventEmitter(), contents = new EventEmitter();
  let attached = false;
  Object.assign(dbg, { isAttached: () => attached, attach: () => { attached = true; }, detach: () => { attached = false; }, sendCommand: client.send });
  Object.assign(contents, { id, debugger: dbg });
  const observer = traffic ? createTrafficObserver({ write, scope, reveal }) : undefined;
  observer?.attach(contents);

  const run = async command => {
    if (command.kind === 'send-marker' && !running) {
      const entry = replays.get(command.replay);
      replays.delete(command.replay);
      try {
        if (!entry) throw new Error('The request is no longer available to resend');
        const body = fillMarkerBody(entry.body, marker, command.fields, active && command.active === true);
        if (!body) throw new Error('The captured fields cannot be replayed');
        const result = await evaluate(`(async () => { const r = await fetch(${JSON.stringify(entry.url)}, ${JSON.stringify({ method: entry.method, body: body.body,
          headers: { ...entry.headers, 'content-type': body.contentType }, credentials: 'include' })}); return { ok: r.ok, status: r.status }; })()`);
        write('marker-request', { route: command.route, method: entry.method, ...result, fields: command.fields.map(field => field.name) });
        if (result?.ok && active && command.active) write('active-payload-sent', { method: entry.method, route: command.route, status: result.status });
      } catch (error) { write('marker-request', { route: command.route, ok: false, error: error.message }); }
      return;
    }
    if (running || !active || !campaign || command.kind !== 'run-campaign') return;
    running = true;
    const campaignMarker = `${marker.slice(0, 50)}_${crypto.randomBytes(8).toString('hex')}`;
    campaignMarkers.add(campaignMarker);
    const campaignWrite = (kind, data) => write(kind, { campaignId: campaignMarker, ...data });
    let receiver, canaryDir;
    const seeded = [];
    try {
      const entry = replays.get(command.replay);
      replays.delete(command.replay);
      if (!entry) throw new Error('The captured request is no longer available');
      const profile = normalizeCampaign({ version: 1, capture: { method: entry.method, route: command.profile?.route?.replace(/^[A-Z]+ /, '') },
        fields: command.profile?.fields, view: command.profile?.view, cases: command.profile?.cases, waitMs: command.profile?.waitMs,
        verify: command.profile?.verify, closeOnDone: false, restoreOnDone: command.profile?.restoreOnDone !== false });
      if (hostsOutsideScope(profile, scope).length) throw new Error('Campaign endpoint is outside --scope');
      if (profile.docxImport || profile.cases.some(name => name.startsWith('api-') || name.startsWith('nav-')))
        throw new Error('Debug attachment currently supports the standard text/HTML campaign cases');
      const viewURL = profile.view === 'captured' ? entry.viewURL : profile.view;
      const view = async name => {
        const destination = viewURL === 'reload' ? currentURL : viewURL;
        let loaded = false;
        const onLoad = method => { if (method === 'Page.loadEventFired') loaded = true; };
        client.events.on('protocol', onLoad);
        try {
          const navigation = await client.send('Page.navigate', { url: destination });
          if (navigation.errorText) throw new Error('Could not navigate to the saved view');
          for (let attempt = 0; attempt < 50; attempt++) {
            if (controller.signal.aborted) return false;
            try {
              if ((!navigation.loaderId || loaded) && await evaluate('document.readyState === "complete"')) {
                if (name === 'javascript-url') {
                  const clicked = await evaluate(`(() => { const link = [...document.querySelectorAll('a[data-eng-campaign]')].find(a => a.getAttribute('data-eng-campaign') === ${JSON.stringify(marker)}); if (!link) return false; link.click(); return true; })()`);
                  write('campaign-action', { case: name, clicked: !!clicked, navigated: false, url: redact(currentURL) });
                }
                return true;
              }
            } catch { /* navigation in progress */ }
            await new Promise(resolve => setTimeout(resolve, 100));
          }
          return false;
        } finally { client.events.removeListener('protocol', onLoad); }
      };
      const seed = async (name, slot) => {
        if (!await view()) throw new Error('Could not open the saved view');
        const data = { name: `eng_campaign_${campaignMarker}_${name}_${slot ?? 0}`, value: crypto.randomBytes(16).toString('hex') };
        const code = name === 'cookie-canary' ? `document.cookie = ${JSON.stringify(`${data.name}=${data.value}; Path=/; SameSite=Lax`)}; return document.cookie.includes(${JSON.stringify(`${data.name}=${data.value}`)});` :
          name === 'localstorage-canary' ? `localStorage.setItem(${JSON.stringify(data.name)}, ${JSON.stringify(data.value)}); return localStorage.getItem(${JSON.stringify(data.name)}) === ${JSON.stringify(data.value)};` :
            `return await new Promise(resolve => { const r = indexedDB.open(${JSON.stringify(data.name)}, 1); r.onupgradeneeded = () => r.result.createObjectStore('canary'); r.onerror = () => resolve(false); r.onsuccess = () => { const db = r.result, tx = db.transaction('canary', 'readwrite'); tx.objectStore('canary').put(${JSON.stringify(data.value)}, 'nonce'); tx.oncomplete = () => { db.close(); resolve(true); }; tx.onerror = () => { db.close(); resolve(false); }; }; });`;
        if (!await evaluate(`(async () => { ${code} })()`)) throw new Error('Could not seed controlled renderer data');
        seeded.push({ ...data, nameOfCase: name });
        return data;
      };
      if (profile.cases.some(name => RESOURCES.has(name))) receiver = await startResourceReceiver(campaignMarker, campaignWrite);
      const canary = () => {
        canaryDir ||= fs.mkdtempSync(path.join(os.tmpdir(), 'eng-debug-canary-'));
        const value = crypto.randomBytes(16).toString('hex'), file = path.join(canaryDir, 'probe.txt');
        fs.writeFileSync(file, value); return { path: file, value };
      };
      const sendRequest = async (url, options) => {
        const result = await evaluate(`(async () => { const r = await fetch(${JSON.stringify(url)}, ${JSON.stringify({ ...options, credentials: 'include' })}); return { ok: r.ok, status: r.status, body: ${options.method === 'GET' ? '(await r.text()).slice(0,100001)' : 'undefined'} }; })()`);
        if (!result) throw new Error('No renderer fetch response was observed');
        return { ...result, text: async () => result.body };
      };
      await runCampaign({ profile: { ...profile, request: { method: entry.method, url: entry.url, body: entry.body, headers: entry.headers }, resourceBase: receiver?.url },
        marker: campaignMarker, campaignId: campaignMarker, fetch: sendRequest, fill: fillMarkerBody, view, write: campaignWrite, canary, seed, signal: controller.signal,
        delay: ms => new Promise(resolve => {
          if (controller.signal.aborted) return resolve();
          const done = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', done); resolve(); };
          const timer = setTimeout(done, ms); controller.signal.addEventListener('abort', done, { once: true });
        }) });
    } catch (error) { write('campaign-error', { message: error.message }); }
    finally {
      let cleaned = true;
      for (const data of seeded) {
        const code = data.nameOfCase === 'cookie-canary' ? `document.cookie = ${JSON.stringify(`${data.name}=; Path=/; Max-Age=0`)}; return !document.cookie.includes(${JSON.stringify(`${data.name}=`)});` :
          data.nameOfCase === 'localstorage-canary' ? `localStorage.removeItem(${JSON.stringify(data.name)}); return localStorage.getItem(${JSON.stringify(data.name)}) === null;` :
            `return await Promise.race([new Promise(resolve => { const r = indexedDB.deleteDatabase(${JSON.stringify(data.name)}); r.onsuccess = () => resolve(true); r.onerror = r.onblocked = () => resolve(false); }), new Promise(resolve => setTimeout(() => resolve(false), 2000))]);`;
        try { cleaned = !!await evaluate(`(async () => { ${code} })()`) && cleaned; } catch { cleaned = false; }
      }
      if (seeded.length) write('campaign-cleanup', { count: seeded.length, ok: cleaned });
      receiver?.server.close(); if (canaryDir) fs.rmSync(canaryDir, { recursive: true, force: true }); running = false;
    }
  };
  const campaignMarkers = new Set([marker]);
  const onProtocol = (method, params) => {
    dbg.emit('message', {}, method, params);
    if (method === 'Runtime.executionContextCreated' && params.context.auxData?.isDefault) contexts.add(params.context.id);
    else if (method === 'Runtime.executionContextDestroyed') contexts.delete(params.executionContextId);
    else if (method === 'Runtime.executionContextsCleared') contexts.clear();
    else if ((method === 'Page.frameNavigated' && !params.frame.parentId) || method === 'Page.navigatedWithinDocument') {
      trace(`navigated ${redact(params.frame?.url || params.url)}`);
      currentURL = params.frame?.url || params.url;
      write('did-navigate', { id, url: redact(currentURL) });
    } else if (method === 'Page.loadEventFired') task(metadata());
    else if (method === 'Runtime.consoleAPICalled') {
      const message = params.args?.map(arg => typeof arg.value === 'string' ? arg.value : '').join(' ');
      if (active && message === `ENG_ACTIVE_EXEC:${marker}`) write('active-payload-executed', { id, url: redact(currentURL) });
      if (campaign && campaignMarkers.has(message?.split(':')[1])) {
        const match = /^ENG_CAMPAIGN:[A-Za-z0-9_-]+:([a-z-]+)(?::([0-7]))?:([a-z-]+)$/.exec(message);
        if (match && CASES.includes(match[1])) write('campaign-result', { campaignId: message.split(':')[1] === marker ? undefined : message.split(':')[1], case: match[1], slot: match[2] === undefined ? undefined : Number(match[2]), signal: match[3], id, url: redact(currentURL) });
      }
    } else if (method === 'Runtime.exceptionThrown') write('page-exception', { url: redact(currentURL), message: params.exceptionDetails.text || 'Renderer exception' });
    else if (method === 'Network.requestWillBeSentExtraInfo') {
      if (copying) {
        if (requestUrls.has(params.requestId)) copyHeaders(requestUrls.get(params.requestId), params.headers);
        else { sentHeaders.set(params.requestId, params.headers); if (sentHeaders.size > 200) sentHeaders.delete(sentHeaders.keys().next().value); }
      }
      if (requests.has(params.requestId)) requests.get(params.requestId).headers = replayHeaders(params.headers);
      else { extraHeaders.set(params.requestId, replayHeaders(params.headers)); if (extraHeaders.size > 200) extraHeaders.delete(extraHeaders.keys().next().value); }
    } else if (method === 'Network.requestWillBeSent') {
      const r = params.request;
      trace(`request ${r.method} ${redact(r.url)} type=${params.type}`);
      if (copying) {
        copyHeaders(r.url, sentHeaders.get(params.requestId) || r.headers);
        sentHeaders.delete(params.requestId);
        requestUrls.set(params.requestId, r.url);
        if (requestUrls.size > 200) requestUrls.delete(requestUrls.keys().next().value);
      }
      if (r.method !== 'GET') trace(`write request ${r.method} ${redact(r.url)} type=${params.type} postData=${r.postData === undefined ? (r.hasPostData ? 'separate' : 'none') : r.postData.length}${running ? ' (campaign running)' : ''}${commands ? '' : ' (no command channel)'}`);
      if (params.redirectResponse) { requests.delete(params.requestId); return; }
      if (running || !commands || !['XHR', 'Fetch'].includes(params.type) || !['POST', 'PUT', 'PATCH'].includes(r.method) || !/^https?:/.test(r.url)) return;
      const body = r.postData === undefined && r.hasPostData ? client.send('Network.getRequestPostData', { requestId: params.requestId }).then(result => result.postData).catch(() => undefined) : Promise.resolve(r.postData);
      requests.set(params.requestId, { method: r.method, url: r.url, body, headers: extraHeaders.get(params.requestId) || replayHeaders(r.headers), viewURL: currentURL });
      extraHeaders.delete(params.requestId);
      if (requests.size > 200) requests.delete(requests.keys().next().value);
    } else if (method === 'Network.responseReceived') {
      if (params.type === 'Document') {
        const response = params.response;
        headerPages.add(redact(response.url));
        if (headerPages.size > 1000) headerPages.delete(headerPages.values().next().value);
        const csp = Object.entries(response.headers || {}).find(([name]) => name.toLowerCase() === 'content-security-policy')?.[1];
        write('response', { webContents: id, url: redact(response.url), resourceType: 'mainFrame', csp });
      }
      const entry = requests.get(params.requestId);
      if (!entry) return;
      requests.delete(params.requestId);
      task((async () => {
        const body = await entry.body;
        trace(`response ${params.response.status} for ${entry.method} ${redact(entry.url)}, body ${typeof body === 'string' ? body.length : typeof body}`);
        if (typeof body !== 'string' || body.length > 100000) return;
        const inspected = inspectBody(body, marker);
        const replay = ++replayId;
        if (inspected.format && params.response.status >= 200 && params.response.status < 300) {
          replays.set(replay, { ...entry, body });
          if (replays.size > 200) replays.delete(replays.keys().next().value);
        }
        write('api', { method: entry.method, url: redact(entry.url), status: params.response.status, webContents: id,
          bodyBytes: Buffer.byteLength(body), htmlBody: inspected.html, bodyFormat: inspected.format, fields: inspected.fields, replay: replays.has(replay) ? replay : undefined });
      })());
    } else if (method === 'Network.loadingFailed') requests.delete(params.requestId);
  };
  client.events.on('protocol', onProtocol);
  let finish;
  const ended = new Promise(resolve => { finish = resolve; });
  const stop = () => finish();
  client.events.once('closed', stop);
  process.once('SIGINT', stop);
  try {
    await client.send('Runtime.enable');
    await client.send('Page.enable');
    await client.send('Network.enable', { maxPostDataSize: 100000 });
    const script = await client.send('Page.addScriptToEvaluateOnNewDocument', { source: rendererObserver(marker, key, true) });
    scriptId = script.identifier;
    await evaluate(rendererObserver(marker, key, true));
    write('start', { observer: 'renderer-cdp', late: true });
    write('debug-coverage', { message: 'Renderer-only debug attachment. Main-process settings, IPC registration, shell calls, permissions, filesystem/module loads, other targets and subframe sink evidence are not observed. Remote source capture and DOCX/API/navigation campaigns are not supported here. Initial CSP response headers may be unavailable until reload.' });
    await metadata();
    let draining = false;
    timer = setInterval(() => {
      if (draining || stopped) return;
      draining = true;
      task(evaluate(`window[${JSON.stringify(key)}]?.drain()`).then(async list => {
        for (const item of list || []) {
          const data = { id, url: redact(currentURL), detail: item.detail, live: item.live };
          if (item.type === 'entry') write('entry', data);
          else if (item.type === 'sink') write('sink', { ...data, sink: item.detail, frames: (item.frames || []).map(frame => ({ ...frame, url: redact(frame.url) })) });
          else write('dom-observed', { ...data, event: item.type });
          if (item.live || ['event-handler', 'javascript-url'].includes(item.type)) await shot('marker');
        }
      }).finally(() => { draining = false; }));
    }, 500);
    if (commands) stopCommands = followLog(commands, command => { task(run(command)); }, 200);
    if (duration) durationTimer = setTimeout(stop, duration * 1000);
    await ended;
  } finally {
    stopped = true;
    controller.abort();
    clearInterval(timer); clearTimeout(durationTimer); stopCommands?.(); process.removeListener('SIGINT', stop);
    if (running) write('campaign-error', { message: 'Debug attachment stopped before the campaign completed; restoration may be incomplete' });
    if (scriptId) await client.send('Page.removeScriptToEvaluateOnNewDocument', { identifier: scriptId }).catch(() => {});
    const cleanup = `window[${JSON.stringify(key)}]?.cleanup()`;
    await Promise.allSettled([evaluate(cleanup), ...[...contexts].map(contextId => client.send('Runtime.evaluate', { expression: cleanup, contextId, returnByValue: true }))]);
    contents.emit('destroyed'); observer?.flush();
    client.events.removeListener('protocol', onProtocol); client.close();
    replays.clear(); requests.clear(); extraHeaders.clear(); requestUrls.clear(); sentHeaders.clear();
    if (copying && Object.keys(copiedHeaders).length) try { fs.writeFileSync(headersFile, JSON.stringify(copiedHeaders), { mode: 0o600 }); } catch { /* best effort */ }
    await Promise.allSettled([...tasks]);
    write('quit', { observer: 'renderer-cdp', appClosed: false });
  }
  return log;
}
