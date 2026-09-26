'use strict';
// Loaded into the main process of the app under test with NODE_OPTIONS=--require by `electronegativity --watch`.
// It only observes: windows and their settings, page loads and their CSP, IPC channel names, shell calls, permission
// requests and certificate errors are appended to the log file as JSON lines. Values are kept to what the report
// needs: URLs lose their query strings, IPC arguments are reduced to their types.
const logFile = process.env.ELECTRONEGATIVITY_WATCH_LOG;
if (logFile && process.versions.electron && process.type === 'browser') {
  // `electron` only becomes available once Electron has set up the app, so instrument it the first time the app loads
  // it: before its own code can register IPC handlers or create windows. ES module apps get it through the ESM
  // loader instead, so also try again as soon as the app's entry point has started.
  const Module = require('module');
  const originalLoad = Module._load;
  let started = false;
  let wrappedElectron;
  Module._load = function (request, ...rest) {
    const loaded = originalLoad.call(this, request, ...rest);
    if (request === 'electron' && loaded && loaded.app) {
      if (!started) {
        started = true;
        wrappedElectron = instrument(loaded);
      }
      // hand the app the wrapped module so its `new BrowserWindow(...)` is observed (preload capture)
      return wrappedElectron || loaded;
    }
    return loaded;
  };
  setImmediate(() => {
    if (started) return;
    try {
      const loaded = originalLoad.call(Module, 'electron', null, false);
      if (loaded && loaded.app) {
        started = true;
        instrument(loaded, true);
      }
    } catch (error) {
      try {
        require('fs').appendFileSync(logFile, JSON.stringify({ t: Date.now(), kind: 'hook-error', message: `electron module unavailable: ${error && error.message}` }) + '\n');
      } catch {
        // nothing more to do
      }
    }
  });
}

function instrument(electron, late) {
  const fs = require('fs');
  const path = require('path');
  const logFile = process.env.ELECTRONEGATIVITY_WATCH_LOG;
  const write = (kind, data) => {
    try {
      fs.appendFileSync(logFile, JSON.stringify({ t: Date.now(), kind, ...data }) + '\n');
    } catch {
      // the log is best effort, never break the app
    }
  };
  const redact = (url) => {
    // data: URLs carry whole documents: keep their type only
    if (/^data:/i.test(String(url))) return `data:${String(url).slice(5).split(/[;,]/)[0] || 'text/plain'},…`;
    try {
      const parsed = new URL(url);
      parsed.search = '';
      parsed.hash = '';
      parsed.username = '';
      parsed.password = '';
      return parsed.href;
    } catch {
      return String(url || '').slice(0, 300);
    }
  };
  const typeOf = (value) => Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
  const safely = (fn) => {
    try {
      fn();
    } catch (error) {
      write('hook-error', { message: String(error && error.message) });
    }
  };
  const PREFS = ['nodeIntegration', 'nodeIntegrationInSubFrames', 'nodeIntegrationInWorker', 'contextIsolation', 'sandbox', 'webSecurity',
    'allowRunningInsecureContent', 'webviewTag', 'experimentalFeatures', 'enableBlinkFeatures', 'javascript'];
  const pickPrefs = (prefs) => {
    const picked = {};
    for (const key of PREFS) if (prefs && key in prefs) picked[key] = prefs[key];
    if (prefs && prefs.preload) picked.preload = path.basename(String(prefs.preload));
    return picked;
  };

  const { app, ipcMain, shell } = electron;
  // name of the renderer observer's global, different for every session
  const OBSERVER_KEY = `__eng_${require('crypto').randomBytes(6).toString('hex')}`;
  write('start', { electron: process.versions.electron, platform: process.platform, late: !!late });

  // preload scripts, by webContents id: getLastWebPreferences() does not report them, so capture them where the window
  // is constructed. The electron exports are getter-only and can't be reassigned, so the app is handed a Proxy of the
  // module (returned from the require hook) that wraps the window constructors. This fills the preload column.
  const wrappedModule = late ? electron : wrapWindowConstructors(electron, write, pickPrefs, path);

  // IPC: channel names the app registers, and the calls the pages make
  const wrapInvoke = (channel, listener) => (event, ...args) => {
    write('ipc', { channel: String(channel), mode: 'invoke', sender: redact(event.senderFrame && event.senderFrame.url), args: args.map(typeOf) });
    return listener(event, ...args);
  };
  safely(() => {
    // started late (ES module app): handlers registered so far are wrapped in place
    const existing = ipcMain._invokeHandlers;
    if (late && existing instanceof Map) {
      for (const [channel, listener] of existing) {
        write('ipc-register', { channel: String(channel), mode: 'handle' });
        existing.set(channel, wrapInvoke(channel, listener));
      }
    }
  });
  safely(() => {
    for (const method of ['handle', 'handleOnce']) {
      const original = ipcMain[method].bind(ipcMain);
      ipcMain[method] = (channel, listener) => {
        write('ipc-register', { channel: String(channel), mode: method });
        return original(channel, wrapInvoke(channel, listener));
      };
    }
    // listeners are passed through unchanged, so removeListener keeps working; calls are seen on webContents below
    for (const method of ['on', 'once', 'addListener', 'prependListener']) {
      const original = ipcMain[method];
      ipcMain[method] = function (channel, ...rest) {
        if (typeof channel === 'string') write('ipc-register', { channel, mode: method });
        return original.call(this, channel, ...rest);
      };
    }
  });

  // shell: what the app opens outside itself
  safely(() => {
    for (const method of ['openExternal', 'openPath', 'showItemInFolder']) {
      const original = shell[method];
      if (typeof original !== 'function') continue;
      shell[method] = function (target, ...rest) {
        write('shell', { method, target: method === 'openExternal' ? redact(target) : String(target) });
        return original.call(this, target, ...rest);
      };
    }
  });

  const instrumentedSessions = new WeakSet();
  function instrumentSession(ses) {
    if (!ses || instrumentedSessions.has(ses)) return;
    instrumentedSessions.add(ses);
    const request = ses.webRequest;
    // response headers of documents and anything fetched over plain http
    const record = (details) => {
      const headers = details.responseHeaders || {};
      const header = (name) => {
        const key = Object.keys(headers).find(k => k.toLowerCase() === name);
        return key ? [].concat(headers[key]).join(', ') : undefined;
      };
      const isDocument = details.resourceType === 'mainFrame' || details.resourceType === 'subFrame';
      if (isDocument || /^http:/i.test(details.url))
        write('response', { url: redact(details.url), resourceType: details.resourceType, status: details.statusCode, webContents: details.webContentsId,
          csp: isDocument ? header('content-security-policy') : undefined, frameOptions: isDocument ? header('x-frame-options') : undefined });
    };
    const originalOnHeaders = request.onHeadersReceived.bind(request);
    let appListener = null;
    originalOnHeaders((details, callback) => {
      record(details);
      if (appListener) appListener(details, callback);
      else callback({});
    });
    // the app setting its own listener replaces ours: keep recording, then hand over to it
    request.onHeadersReceived = (filterOrListener, maybeListener) => {
      const listener = typeof filterOrListener === 'function' || filterOrListener === null ? filterOrListener : maybeListener;
      const filter = typeof filterOrListener === 'object' && filterOrListener !== null ? filterOrListener : undefined;
      appListener = listener;
      const combined = (details, callback) => {
        record(details);
        if (appListener) appListener(details, callback);
        else callback({});
      };
      return filter ? originalOnHeaders(filter, combined) : originalOnHeaders(combined);
    };

    // permission requests and the answers; without a handler of the app's own, Electron grants everything
    const originalSetHandler = ses.setPermissionRequestHandler.bind(ses);
    const logged = (handler, isDefault) => (webContents, permission, callback, details) => {
      const answer = (granted) => {
        write('permission', { permission, origin: redact((details && details.requestingUrl) || (webContents && webContents.getURL())), granted: !!granted, default: isDefault });
        callback(granted);
      };
      if (handler) handler(webContents, permission, answer, details);
      else answer(true);
    };
    originalSetHandler(logged(null, true));
    ses.setPermissionRequestHandler = (handler) => originalSetHandler(handler ? logged(handler, false) : logged(null, true));

    // synchronous permission checks (setPermissionCheckHandler): without a handler of the app's own, Electron
    // answers them itself. Records what the app's handler (or the default) allows, the same way as requests above.
    if (typeof ses.setPermissionCheckHandler === 'function') {
      const originalSetCheck = ses.setPermissionCheckHandler.bind(ses);
      const loggedCheck = (handler, isDefault) => (webContents, permission, requestingOrigin, details) => {
        const granted = handler ? handler(webContents, permission, requestingOrigin, details) : true;
        write('permission-check', { permission, origin: redact(requestingOrigin || (details && details.requestingUrl) || (webContents && webContents.getURL && webContents.getURL())), granted: !!granted, default: isDefault });
        return granted;
      };
      originalSetCheck(loggedCheck(null, true));
      ses.setPermissionCheckHandler = (handler) => originalSetCheck(handler ? loggedCheck(handler, false) : loggedCheck(null, true));
    }
  }

  const instrumented = new WeakSet();
  function instrumentWebContents(contents) {
    if (instrumented.has(contents)) return;
    instrumented.add(contents);
    const id = contents.id;
    let type = 'unknown';
    safely(() => { type = contents.getType(); });
    safely(() => instrumentSession(contents.session));
    write('webcontents', { id, type });

    const prefs = () => {
      try {
        return pickPrefs(contents.getLastWebPreferences());
      } catch {
        return {};
      }
    };
    contents.on('did-finish-load', () => {
      const url = redact(contents.getURL());
      write('page', { id, type, url, prefs: prefs() });
      // a CSP can also come from a <meta> tag: read it from the page (read-only)
      contents.executeJavaScript(`(() => { const m = document.querySelector('meta[http-equiv="Content-Security-Policy" i]'); return m ? m.getAttribute('content') : null; })()`, false)
        .then(csp => write('page-meta-csp', { id, url, csp }))
        .catch(() => {});
    });
    contents.on('will-navigate', (event, url) => write('will-navigate', { id, url: redact(url) }));
    contents.on('did-navigate', (event, url) => write('did-navigate', { id, url: redact(url) }));
    contents.on('did-create-window', (window, details) => write('child-window', { id, url: redact(details && details.url), disposition: details && details.disposition }));
    contents.on('will-attach-webview', (event, webPreferences, params) => {
      // read after the app's own handlers, which may change the options or cancel the webview
      setImmediate(() => write('webview', { id, src: redact(params && params.src), prefs: pickPrefs(webPreferences), prevented: !!event.defaultPrevented }));
    });
    const onMessage = (mode) => (event, channel, ...args) =>
      write('ipc', { channel: String(channel), mode, sender: redact(event.senderFrame && event.senderFrame.url), args: args.map(typeOf), webContents: id });
    contents.on('ipc-message', onMessage('send'));
    contents.on('ipc-message-sync', onMessage('sendSync'));

    // renderer-side observer: watch mode otherwise only sees the main process. A small script installed in the page
    // reports DOM changes that carry script (inserted <script>, on* handlers, javascript: URLs) and whether a planted
    // marker (--watch-marker) comes back rendered as live HTML. It is read-only and best effort: it never blocks the app.
    if (type === 'window' || type === 'webview' || type === 'browserView') {
      const install = () => contents.executeJavaScript(rendererObserver(process.env.ELECTRONEGATIVITY_WATCH_MARKER), false).catch(() => {});
      const drain = () => {
        if (contents.isDestroyed()) return;
        const url = redact(contents.getURL());
        contents.executeJavaScript(`(window[${JSON.stringify(OBSERVER_KEY)}] ? window[${JSON.stringify(OBSERVER_KEY)}].drain() : [])`, false)
          .then(list => { for (const e of (list || [])) write('dom-observed', { id, url, event: e.type, detail: e.detail, live: e.live }); })
          .catch(() => {});
      };
      contents.on('dom-ready', () => { install(); });
      const timer = setInterval(drain, 500);
      if (timer.unref) timer.unref();
      contents.once('destroyed', () => clearInterval(timer));
      contents.on('did-finish-load', () => setTimeout(drain, 100));
    }
  }

  // Script installed into each page. Buffers script-bearing DOM insertions and marker reflections; the main process
  // pulls them with drain(). Kept dependency-free and defensive so it runs under any page's CSP and isolation settings.
  function rendererObserver(marker) {
    return `(() => { try {
      var KEY = ${JSON.stringify(OBSERVER_KEY)};
      if (window[KEY]) return 'exists';
      var events = [], seen = {};
      var push = function (e) { var k = e.type + '|' + (e.detail || '') + '|' + (e.live === undefined ? '' : e.live); if (seen[k]) return; seen[k] = 1; events.push(e); };
      var MARKER = ${JSON.stringify(marker || null)};
      var inspect = function (node) {
        if (!node || node.nodeType !== 1) return;
        if (node.tagName === 'SCRIPT' && (node.src || (node.textContent || '').trim())) push({ type: 'script', detail: node.src ? 'src' : 'inline' });
        var attrs = node.attributes || [];
        for (var i = 0; i < attrs.length; i++) {
          var a = attrs[i];
          // an event handler attribute: onclick, onerror... (not onboarding="true"): the element has a matching property
          if (/^on[a-z]+$/i.test(a.name) && (a.name.toLowerCase() in node)) push({ type: 'event-handler', detail: a.name });
          if (/^\\s*javascript:/i.test(a.value || '')) push({ type: 'javascript-url', detail: a.name });
        }
      };
      var scan = function (node) { inspect(node); if (node.querySelectorAll) { var all = node.querySelectorAll('*'); for (var i = 0; i < all.length; i++) inspect(all[i]); } };
      var mo = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var m = muts[i];
          if (m.type === 'attributes') inspect(m.target);
          var added = m.addedNodes || [];
          for (var j = 0; j < added.length; j++) scan(added[j]);
        }
      });
      var checkMarker = function () {
        if (!MARKER) return;
        try {
          var live = false, present = false;
          var els = document.getElementsByTagName('*');
          for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') continue; // their text is source, not rendered markup
            var attrs = el.attributes || [];
            for (var j = 0; j < attrs.length; j++) {
              var name = attrs[j].name.toLowerCase(), value = attrs[j].value || '';
              // the marker shaped the markup: it became an attribute name, or landed in an event handler. Text in an
              // ordinary attribute value (an input's value, a title) is how safely displayed content looks.
              if (name.indexOf(MARKER.toLowerCase()) !== -1) { live = true; present = true; }
              else if (value.indexOf(MARKER) !== -1) { present = true; if (/^on/.test(name)) live = true; }
            }
            if (el.tagName && el.tagName.indexOf(MARKER.toUpperCase()) !== -1) { live = true; present = true; } // marker as a tag name
          }
          var shown = (document.body && (document.body.innerText || document.body.textContent)) || '';
          if (shown.indexOf(MARKER) !== -1) present = true; // marker visible as text (escaped, or alongside a live copy)
          if (present) push({ type: 'marker', detail: MARKER, live: live });
        } catch (e) {}
      };
      // a per-session name, hidden from enumeration and read-only, so pages don't trip over it or replace it
      Object.defineProperty(window, KEY, { value: Object.freeze({ drain: function () { checkMarker(); return events.splice(0); } }), enumerable: false, writable: false, configurable: false });
      var start = function () { try { mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true }); } catch (e) {} scan(document.documentElement); checkMarker(); };
      if (document.documentElement) start(); else document.addEventListener('DOMContentLoaded', start);
      return 'installed';
    } catch (e) { return 'error:' + (e && e.message); } })()`;
  }

  app.on('web-contents-created', (event, contents) => instrumentWebContents(contents));
  app.on('session-created', (ses) => safely(() => instrumentSession(ses)));
  app.on('certificate-error', (event, contents, url, error) => write('certificate-error', { url: redact(url), error: String(error) }));
  app.whenReady().then(() => safely(() => instrumentSession(electron.session.defaultSession)));
  app.on('quit', () => write('quit', {}));

  return wrappedModule;
}

// A Proxy of the electron module whose BrowserWindow/BrowserView/WebContentsView constructors are wrapped to record the
// preload script (and other webPreferences) each window is built with. The exports are getter-backed but not
// non-configurable data properties, so a get trap may return a wrapped value; instances keep passing `instanceof`.
function wrapWindowConstructors(electron, write, pickPrefs, path) {
  const CTORS = new Set(['BrowserWindow', 'BrowserView', 'WebContentsView']);
  const cache = new WeakMap();
  return new Proxy(electron, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (!CTORS.has(prop) || typeof value !== 'function') return value;
      if (!cache.has(value)) {
        cache.set(value, new Proxy(value, {
          construct(ctor, args, newTarget) {
            const instance = Reflect.construct(ctor, args, newTarget);
            try {
              const prefs = (args && args[0] && args[0].webPreferences) || {};
              const contents = instance && instance.webContents;
              write('window', { id: contents && typeof contents.id === 'number' ? contents.id : undefined, ctor: prop,
                preload: prefs.preload ? path.basename(String(prefs.preload)) : undefined, prefs: pickPrefs(prefs) });
            } catch (error) {
              write('hook-error', { message: `window record failed: ${error && error.message}` });
            }
            return instance;
          }
        }));
      }
      return cache.get(value);
    }
  });
}
