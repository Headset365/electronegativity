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
  let started = false;
  let wrappedElectron;
  // wraps a module loader so the first load of `electron` is instrumented, and the app gets the wrapped module
  const wrapLoader = (load) => function (request, ...rest) {
    const loaded = load.call(this, request, ...rest);
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
  const originalLoad = Module._load;
  let currentLoad = wrapLoader(originalLoad);
  // Electron installs its own Module._load (which answers `electron` itself) after NODE_OPTIONS=--require has run on
  // some releases (34): keep wrapping whatever loader is installed later, so `electron` still passes through here
  try {
    Object.defineProperty(Module, '_load', {
      configurable: true,
      enumerable: true,
      get() { return currentLoad; },
      set(load) { currentLoad = typeof load === 'function' ? wrapLoader(load) : load; },
    });
  } catch {
    Module._load = currentLoad;
  }
  setImmediate(() => {
    if (started) return;
    try {
      const loaded = Module._load.call(Module, 'electron', null, false);
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
  // the planted marker (--watch-marker): where it turns up is recorded as a yes/no, so a finding that needs review can be
  // confirmed at runtime (content reaching openExternal, a navigation, IPC, a command line), without logging the values
  const MARKER = process.env.ELECTRONEGATIVITY_WATCH_MARKER || '';
  const hasMarker = (value) => {
    if (!MARKER || value === undefined || value === null) return false;
    try {
      return (typeof value === 'string' ? value : JSON.stringify(value) || String(value)).includes(MARKER);
    } catch {
      return false;
    }
  };
  const schemeOf = (url) => (String(url).match(/^([a-z][\w+.-]*):/i) || [])[1];
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
    write('ipc', { channel: String(channel), mode: 'invoke', sender: redact(event.senderFrame && event.senderFrame.url), args: args.map(typeOf), marker: hasMarker(args) });
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
        write('shell', { method, target: method === 'openExternal' ? redact(target) : String(target), marker: hasMarker(target),
          scheme: method === 'openExternal' ? schemeOf(target) : undefined });
        return original.call(this, target, ...rest);
      };
    }
  });

  // commands the main process runs: only the program name, and whether the marker was part of the command line
  safely(() => {
    const childProcess = require('child_process');
    for (const method of ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync']) {
      const original = childProcess[method];
      if (typeof original !== 'function') continue;
      const wrapped = function (command, ...rest) {
        try {
          const args = Array.isArray(rest[0]) ? rest[0] : [];
          write('process', { method, program: path.basename(String(command).trim().split(/\s+/)[0] || ''), marker: hasMarker(command) || hasMarker(args) });
        } catch {
          // observing never breaks the call
        }
        return original.call(this, command, ...rest);
      };
      // keep what hangs off the original, util.promisify.custom above all (promisify(exec) resolves { stdout, stderr })
      Object.defineProperties(wrapped, Object.getOwnPropertyDescriptors(original));
      childProcess[method] = wrapped;
    }
  });

  // Front-end code the pages run, captured for the static scan (a remote web app is not in the package): documents,
  // scripts and HTML templates, downloaded again with the page's own session (so a logged-in test account's cookies
  // apply) into capture/ next to the log. Source maps are fetched too, to scan the original code.
  const CAPTURE_DIR = process.env.ELECTRONEGATIVITY_WATCH_CAPTURE === '1' ? path.join(path.dirname(logFile), 'capture') : null;
  const MAX_CAPTURES = 400;
  const MAX_CAPTURE_BYTES = 30 * 1024 * 1024;
  const captured = new Set();
  let captureCount = 0;
  const appendCapture = (entry) => {
    try {
      fs.mkdirSync(path.join(CAPTURE_DIR, 'files'), { recursive: true });
      fs.appendFileSync(path.join(CAPTURE_DIR, 'manifest.jsonl'), JSON.stringify(entry) + '\n');
    } catch {
      // best effort
    }
  };
  const saveCapture = (body, extension) => {
    const file = `files/w${++captureCount}${extension}`;
    fs.mkdirSync(path.join(CAPTURE_DIR, 'files'), { recursive: true });
    fs.writeFileSync(path.join(CAPTURE_DIR, file), body);
    return file;
  };
  const download = (ses, url) => ses.fetch(url, { method: 'GET' })
    .then(response => response.ok ? response.arrayBuffer() : null)
    .then(buffer => buffer && buffer.byteLength <= MAX_CAPTURE_BYTES ? Buffer.from(buffer) : null);
  function capture(details, ses) {
    if (!CAPTURE_DIR || details.webContentsId === undefined || details.method !== 'GET' || !/^https?:/i.test(details.url)) return;
    if (details.statusCode >= 400) return;
    let pathname;
    try {
      pathname = new URL(details.url).pathname;
    } catch {
      return;
    }
    const kind = details.resourceType === 'mainFrame' || details.resourceType === 'subFrame' ? 'page'
      : details.resourceType === 'script' ? 'script'
        : (details.resourceType === 'xhr' || details.resourceType === 'other') && /\.html?$/i.test(pathname) ? 'template' : undefined;
    if (!kind) return;
    const label = redact(details.url);
    if (captured.has(label) || captured.size >= MAX_CAPTURES) return;
    captured.add(label);
    const entry = { kind, url: label };
    // without session.fetch (Electron < 25) only the URL is recorded, and the CLI fetches it afterwards
    if (typeof ses.fetch !== 'function') return appendCapture(entry);
    download(ses, details.url).then(body => {
      if (!body) return appendCapture(entry);
      entry.file = saveCapture(body, kind === 'script' ? '.js' : '.html');
      appendCapture(entry);
      if (kind !== 'script') return;
      const tail = body.subarray(Math.max(0, body.length - 4096)).toString('utf8');
      const reference = [...tail.matchAll(/[#@]\s*sourceMappingURL=([^\s'"*]+)/g)].pop();
      if (!reference || /^data:/i.test(reference[1])) return; // inline maps are read from the script itself
      const mapUrl = new URL(reference[1], details.url).href;
      if (!/^https?:/i.test(mapUrl)) return;
      return download(ses, mapUrl).then(map => { if (map) appendCapture({ kind: 'map', url: redact(mapUrl), of: label, file: saveCapture(map, '.map') }); });
    }).catch(() => appendCapture(entry));
  }

  // API requests pages make (fetch/XHR), for server-side testing: the endpoints the app talks to, and which of them were
  // sent HTML in the request body. Only whether the body looks like markup and its size are kept, never the content.
  const MARKUP = /<\s*[a-z][\w-]*[\s>/]|&lt;\s*[a-z][\w-]*|\\u003c\s*[a-z]/i;
  const requestBodies = new Map();
  // the names of the fields a request body carries (JSON paths, form fields), each with whether its value looks like
  // markup and whether it holds the marker: the validation assistant asks for the marker in them. Values are not kept.
  const bodyFields = (text) => {
    const fields = [];
    const add = (name, value) => {
      if (fields.length < 60 && typeof value === 'string') fields.push({ name, html: MARKUP.test(value), marker: hasMarker(value) });
    };
    const walk = (value, name, depth) => {
      if (depth > 6 || fields.length >= 60) return;
      if (Array.isArray(value)) value.slice(0, 20).forEach(item => walk(item, `${name}[]`, depth + 1));
      else if (value && typeof value === 'object') for (const key of Object.keys(value)) walk(value[key], name ? `${name}.${key}` : key, depth + 1);
      else add(name || '(body)', value);
    };
    const trimmed = text.trim();
    if (/^[[{]/.test(trimmed)) {
      try {
        walk(JSON.parse(trimmed), '', 0);
        return fields;
      } catch {
        // not JSON after all
      }
    }
    if (/^[\w.%[\]-]+=/.test(trimmed) && !/\s/.test(trimmed.slice(0, 200))) {
      for (const [name, value] of new URLSearchParams(trimmed)) add(name, value);
      return fields;
    }
    for (const [, name, value] of trimmed.matchAll(/name="([^"]{1,100})"(?:; filename="[^"]*")?\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]*?)\r?\n--/g)) add(name, value);
    return fields;
  };
  const inspectBody = (details) => {
    if (details.resourceType !== 'xhr' || !Array.isArray(details.uploadData) || details.uploadData.length === 0) return;
    let bytes = 0;
    let text = '';
    for (const part of details.uploadData) {
      if (!part || !part.bytes) continue;
      bytes += part.bytes.length;
      if (text.length < 1024 * 1024) text += part.bytes.subarray(0, 1024 * 1024 - text.length).toString('utf8');
    }
    let fields = [];
    try {
      fields = bodyFields(text);
    } catch {
      // unreadable body
    }
    requestBodies.set(details.id, { bytes, html: MARKUP.test(text), fields, marker: hasMarker(text) });
    if (requestBodies.size > 5000) requestBodies.delete(requestBodies.keys().next().value);
  };
  const recordApi = (details) => {
    if (details.resourceType !== 'xhr' || details.webContentsId === undefined || !/^https?:/i.test(details.url)) return;
    const body = requestBodies.get(details.id);
    requestBodies.delete(details.id);
    write('api', { method: details.method, url: redact(details.url), status: details.statusCode, webContents: details.webContentsId,
      bodyBytes: body ? body.bytes : 0, htmlBody: !!(body && body.html), fields: body && body.fields.length ? body.fields : undefined,
      marker: !!(body && body.marker) });
  };

  // webRequest allows one listener per event and session: ours observes, then hands over to the app's own listener,
  // which it keeps receiving when the app sets it later
  function chainListener(request, name, observe) {
    const original = request[name].bind(request);
    let appListener = null;
    const combined = (details, callback) => {
      try {
        observe(details);
      } catch {
        // observing never breaks a request
      }
      if (appListener) appListener(details, callback);
      else callback({});
    };
    original(combined);
    request[name] = (filterOrListener, maybeListener) => {
      const listener = typeof filterOrListener === 'function' || filterOrListener === null ? filterOrListener : maybeListener;
      const filter = typeof filterOrListener === 'object' && filterOrListener !== null ? filterOrListener : undefined;
      appListener = listener;
      return filter ? original(filter, combined) : original(combined);
    };
  }

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
      recordApi(details);
      capture(details, ses);
    };
    chainListener(request, 'onBeforeRequest', inspectBody);
    chainListener(request, 'onHeadersReceived', record);

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
    contents.on('will-navigate', (event, url) => {
      // read after the app's own handlers, which may cancel it
      setImmediate(() => write('will-navigate', { id, url: redact(url), marker: hasMarker(url), prevented: !!event.defaultPrevented }));
    });
    contents.on('did-navigate', (event, url) => write('did-navigate', { id, url: redact(url), marker: hasMarker(url) }));
    contents.on('did-create-window', (window, details) => write('child-window', { id, url: redact(details && details.url), disposition: details && details.disposition, marker: hasMarker(details && details.url) }));
    // window.open() and target=_blank links, with what the app's handler decided (the default allows them)
    safely(() => {
      const originalSetHandler = contents.setWindowOpenHandler.bind(contents);
      const logged = (handler) => (details) => {
        const result = handler ? handler(details) : { action: 'allow' };
        write('window-open', { id, url: redact(details && details.url), marker: hasMarker(details && details.url), action: (result && result.action) || 'allow', default: !handler });
        return result;
      };
      originalSetHandler(logged(null));
      contents.setWindowOpenHandler = (handler) => originalSetHandler(logged(handler));
    });
    contents.on('will-attach-webview', (event, webPreferences, params) => {
      // read after the app's own handlers, which may change the options or cancel the webview
      setImmediate(() => write('webview', { id, src: redact(params && params.src), prefs: pickPrefs(webPreferences), prevented: !!event.defaultPrevented }));
    });
    const onMessage = (mode) => (event, channel, ...args) =>
      write('ipc', { channel: String(channel), mode, sender: redact(event.senderFrame && event.senderFrame.url), args: args.map(typeOf), webContents: id, marker: hasMarker(args) });
    contents.on('ipc-message', onMessage('send'));
    contents.on('ipc-message-sync', onMessage('sendSync'));

    // renderer-side observer: watch mode otherwise only sees the main process. A small script installed in the page
    // reports DOM changes that carry script (inserted <script>, on* handlers, javascript: URLs) and whether a planted
    // marker (--watch-marker) comes back rendered as live HTML. It is read-only and best effort: it never blocks the app.
    if (type === 'window' || type === 'webview' || type === 'browserView') {
      // every frame of the page, not only the top one: rich-text editors (TinyMCE, CKEditor 4) show the document inside
      // an iframe, which is where stored content is rendered. Frames that appear later (an editor initialising) get the
      // observer on the next poll.
      const observerCode = rendererObserver(process.env.ELECTRONEGATIVITY_WATCH_MARKER);
      const drainCode = `(window[${JSON.stringify(OBSERVER_KEY)}] ? window[${JSON.stringify(OBSERVER_KEY)}].drain() : null)`;
      const frames = () => {
        try {
          const main = contents.mainFrame;
          if (main && Array.isArray(main.framesInSubtree)) return main.framesInSubtree.map(frame => ({ frame, top: frame === main }));
        } catch {
          // frames are gone while the page navigates
        }
        return [{ frame: contents, top: true }]; // Electron without WebFrameMain: the top frame only
      };
      const install = () => {
        for (const { frame } of frames()) Promise.resolve().then(() => frame.executeJavaScript(observerCode, false)).catch(() => {});
      };
      const drain = () => {
        if (contents.isDestroyed()) return;
        const url = redact(contents.getURL());
        for (const { frame, top } of frames()) {
          let frameUrl;
          try {
            frameUrl = top ? undefined : redact(frame.url) || 'about:blank';
          } catch {
            frameUrl = undefined;
          }
          Promise.resolve().then(() => frame.executeJavaScript(drainCode, false))
            .then(list => {
              if (list === null) return frame.executeJavaScript(observerCode, false); // not installed yet in this frame
              for (const e of (list || [])) {
                if (e.type === 'entry') write('entry', { id, url, detail: e.detail, frame: frameUrl });
                else if (e.type === 'sink') write('sink', { id, url, frame: frameUrl, sink: e.detail, live: e.live, frames: (e.frames || []).map(f => ({ ...f, url: redact(f.url) })) });
                else write('dom-observed', { id, url, frame: frameUrl, event: e.type, detail: e.detail, live: e.live });
              }
            })
            .catch(() => {});
        }
      };
      contents.on('dom-ready', () => { install(); });
      contents.on('did-frame-finish-load', () => { install(); });
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
      // HTML sinks: when a value carrying the marker is written as HTML, record the sink and the script location that
      // did it, so the static finding at that line can be confirmed. Only values holding the marker are looked at.
      var frames = function () {
        var list = [];
        String(new Error().stack || '').split('\\n').forEach(function (line) {
          var m = line.match(/([a-z][\\w+.-]*:\\/\\/[^\\s()]+):(\\d+):(\\d+)/i);
          if (m && list.length < 6) list.push({ url: m[1], line: Number(m[2]), column: Number(m[3]) });
        });
        return list;
      };
      var sinkSeen = {};
      var sink = function (name, value) {
        try {
          if (!MARKER || typeof value !== 'string' || value.indexOf(MARKER) === -1) return;
          var f = frames();
          var live = new RegExp('<[a-z][^>]*' + MARKER, 'i').test(value);
          var key = name + '|' + live + '|' + (f[0] ? f[0].url + ':' + f[0].line + ':' + f[0].column : '');
          if (sinkSeen[key]) return;
          sinkSeen[key] = 1;
          events.push({ type: 'sink', detail: name, live: live, frames: f });
        } catch (e) {}
      };
      if (MARKER) {
        try {
          ['innerHTML', 'outerHTML'].forEach(function (prop) {
            var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
            if (!d || !d.set || !d.configurable) return;
            Object.defineProperty(Element.prototype, prop, { configurable: true, enumerable: d.enumerable, get: d.get, set: function (v) { sink(prop, v); return d.set.call(this, v); } });
          });
          var wrap = function (proto, name, argIndex) {
            var original = proto && proto[name];
            if (typeof original !== 'function') return;
            proto[name] = function () { sink(name, arguments[argIndex]); return original.apply(this, arguments); };
          };
          wrap(Element.prototype, 'insertAdjacentHTML', 1);
          wrap(Document.prototype, 'write', 0);
          wrap(Document.prototype, 'writeln', 0);
          wrap(window.Range && Range.prototype, 'createContextualFragment', 0);
        } catch (e) {}
      }
      // a per-session name, hidden from enumeration and read-only, so pages don't trip over it or replace it
      Object.defineProperty(window, KEY, { value: Object.freeze({ drain: function () { checkMarker(); return events.splice(0); } }), enumerable: false, writable: false, configurable: false });
      // entry points the user exercised (for coverage): paste, drag and drop, file pickers. Only the kind is kept.
      var types = function (list) { try { return Array.prototype.slice.call(list || []); } catch (e) { return []; } };
      window.addEventListener('paste', function (e) { var t = types(e.clipboardData && e.clipboardData.types); push({ type: 'entry', detail: t.indexOf('text/html') !== -1 ? 'paste-html' : t.indexOf('Files') !== -1 ? 'paste-file' : 'paste-text' }); }, true);
      window.addEventListener('drop', function (e) { var t = types(e.dataTransfer && e.dataTransfer.types); push({ type: 'entry', detail: t.indexOf('Files') !== -1 ? 'drop-file' : t.indexOf('text/html') !== -1 ? 'drop-html' : 'drop-text' }); }, true);
      document.addEventListener('change', function (e) { if (e.target && e.target.type === 'file') push({ type: 'entry', detail: 'file-picker' }); }, true);
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
  // files, deep links and command lines handed to the app (listening does not change how the app handles them)
  app.on('open-file', () => write('entry', { detail: 'open-file' }));
  app.on('open-url', () => write('entry', { detail: 'open-url' }));
  app.on('second-instance', () => write('entry', { detail: 'second-instance' }));
  safely(() => {
    const { dialog } = electron;
    for (const method of ['showOpenDialog', 'showOpenDialogSync']) {
      const original = dialog[method];
      if (typeof original !== 'function') continue;
      dialog[method] = function (...args) {
        write('entry', { detail: 'open-dialog' });
        return original.apply(this, args);
      };
    }
  });

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
