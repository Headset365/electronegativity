'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const path = require('node:path');
const fs = require('node:fs');

// electron-trpc's documented ETRPCRequest envelope. Never infer a procedure from
// an arbitrary payload.path (which may simply be a file name).
function rpcMetadata(channel, args, marker = '') {
  if (!/^(?:electron-trpc|trpc)$/i.test(channel)) return {};
  const own = (object, name) => {
    try { return object && typeof object === 'object' ? Object.getOwnPropertyDescriptor(object, name)?.value : undefined; } catch { return undefined; }
  };
  const value = own(args, '0'), operation = own(value, 'operation');
  if (own(value, 'method') !== 'request' || !operation) return {};
  const procedure = own(operation, 'path'), type = own(operation, 'type');
  if (!/^[\w$-]+(?:\.[\w$-]+){0,12}$/.test(procedure || '') || !['query', 'mutation', 'subscription'].includes(type)) return {};
  const inputMarker = !!marker && containsMarker(own(operation, 'input'), marker);
  return { procedure, rpcType: type, inputMarker };
}
function containsMarker(value, marker) {
  const seen = new WeakSet(); let remaining = 500;
  const walk = (item, depth) => {
    if (--remaining < 0 || depth > 8) return false;
    if (typeof item === 'string') return item.includes(marker);
    if (!item || typeof item !== 'object' || ArrayBuffer.isView(item) || seen.has(item)) return false;
    seen.add(item);
    try { return Object.keys(item).slice(0, Math.max(0, remaining)).some(key => {
      const d = Object.getOwnPropertyDescriptor(item, key); return d && 'value' in d && walk(d.value, depth + 1);
    }); } catch { return false; }
  };
  return walk(value, 0);
}
function frames() {
  return String(new Error().stack || '').split('\n').flatMap(line => {
    const m = line.match(/(?:\(|at )(.+):(\d+):(\d+)\)?$/);
    return m && !m[1].includes(__dirname) && !m[1].startsWith('node:') ? [{ url: m[1], line: Number(m[2]), column: Number(m[3]) }] : [];
  }).slice(0, 8);
}
function messageHosts(args) {
  const hosts = new Set(), seen = new WeakSet(); let remaining = 300;
  const walk = (value, depth) => {
    if (--remaining < 0 || depth > 5 || hosts.size >= 12) return;
    if (typeof value === 'string' && value.length < 2048) {
      try { const u = new URL(value); if (['https:', 'http:'].includes(u.protocol)) hosts.add(u.hostname.toLowerCase()); } catch { /* not a URL */ }
    } else if (value && typeof value === 'object' && !ArrayBuffer.isView(value) && !seen.has(value)) {
      seen.add(value);
      // Avoid invoking getters while observing an application's objects.
      try { for (const key of Object.keys(value).slice(0, Math.max(0, remaining))) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key); if (descriptor && 'value' in descriptor) walk(descriptor.value, depth + 1);
      } } catch { /* unobservable proxy */ }
    }
  };
  walk(args, 0); return [...hosts];
}
function createPassiveEvidence({ write, marker = '', logFile, cwd = () => process.cwd(), now = Date.now } = {}) {
  const context = new AsyncLocalStorage(), wrapped = new WeakMap(), destinations = new Map(), writes = new Map();
  let serial = 0; const records = new Map();
  // Routine autosaves must not exhaust the budget reserved for later SQL/IPC
  // marker evidence. Each record family has its own bounded allowance.
  const emit = (kind, data) => {
    const count = records.get(kind) || 0; records.set(kind, count + 1);
    if (count < 700) try { write(kind, data); } catch { /* observation cannot break the app */ }
  };
  const bounded = (map, key, value) => { map.delete(key); map.set(key, value); if (map.size > 200) map.delete(map.keys().next().value); };
  const wrap = (object, name, factory) => {
    if (!object || typeof object[name] !== 'function') return;
    let names = wrapped.get(object); if (!names) wrapped.set(object, names = new Set());
    if (names.has(name)) return;
    const original = object[name];
    try {
      const replacement = factory(original);
      for (const key of Reflect.ownKeys(original)) if (!['length', 'name', 'prototype', 'caller', 'arguments'].includes(key))
        try { Object.defineProperty(replacement, key, Object.getOwnPropertyDescriptor(original, key)); } catch { /* native metadata */ }
      object[name] = replacement; if (object[name] !== original) names.add(name);
    } catch { /* immutable native export */ }
  };
  const sql = (driver, method, text, preparedFrames = []) => {
    if (typeof text !== 'string' || !marker || !text.includes(marker)) return;
    emit('sql-marker', { driver, method, markerInSql: true, sqlLength: text.length, frames: [...preparedFrames, ...frames()].slice(0, 12), scope: 'database-api-call', ...context.getStore() });
  };
  const statement = (value, driver, text, preparedFrames) => {
    for (const name of ['run', 'get', 'all', 'each', 'iterate']) wrap(value, name, original => function (...args) {
      sql(driver, name, text, preparedFrames); return original.apply(this, args);
    });
    return value;
  };
  function observeModule(name, loaded) {
    if (/^(?:node-adodb|better-sqlite3|sqlite3)$/.test(name)) try {
      if (name === 'node-adodb') wrap(loaded, 'open', original => function (...args) {
        const connection = original.apply(this, args);
        for (const method of ['query', 'execute', 'transaction']) wrap(connection, method, fn => function (text, ...rest) {
          if (Array.isArray(text)) text.slice(0, 100).forEach(value => sql(name, method, value)); else sql(name, method, text);
          return fn.call(this, text, ...rest);
        });
        return connection;
      });
      else {
        const prototype = name === 'sqlite3' ? loaded.Database?.prototype : (loaded.default || loaded).prototype;
        for (const method of name === 'sqlite3' ? ['run', 'get', 'all', 'each', 'exec'] : ['exec']) wrap(prototype, method, fn => function (text, ...rest) {
          sql(name, method, text); return fn.call(this, text, ...rest);
        });
        wrap(prototype, 'prepare', fn => function (text, ...rest) { const origin = frames(); return statement(fn.call(this, text, ...rest), name, text, origin); });
      }
    } catch { emit('passive-coverage', { driver: name, status: 'not-instrumented' }); }
    return loaded;
  }
  function observeIpc(channel, args, sender) {
    const rpc = rpcMetadata(channel, args, marker);
    const hosts = messageHosts(args);
    if (hosts.length) {
      const source = { channel, sender, hosts, at: now() };
      for (const host of hosts) bounded(destinations, `${channel}:${host}`, source);
      emit('ipc-hosts', source);
    }
    return rpc;
  }
  const runIpc = (channel, args, sender, work) => context.run({ channel, ...rpcMetadata(channel, args, marker), ipcCall: ++serial }, work);
  function navigation(url, id) {
    let host; try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
    for (const source of new Set(destinations.values())) if (source.hosts.includes(host) && now() >= source.at && now() - source.at < 600000)
      emit('ipc-state-destination', { channel: source.channel, sender: source.sender, host, id, elapsedMs: now() - source.at, correlationOnly: true });
  }
  const keyOf = file => {
    try {
      if (typeof file === 'string' && /^file:/i.test(file)) file = new URL(file);
      if (file instanceof URL && file.protocol === 'file:') file = require('node:url').fileURLToPath(file);
    } catch { return undefined; }
    if (typeof file !== 'string' || file.includes('\0')) return undefined;
    const resolved = path.resolve(cwd(), file);
    // Reports may sit beside the app's isolated profile. Exclude the log itself,
    // not its entire parent tree (which can contain real app writes).
    if (logFile && (process.platform === 'win32' ? resolved.toLowerCase() === path.resolve(logFile).toLowerCase() : resolved === path.resolve(logFile))) return undefined;
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  };
  function fileWrite(file, method) {
    const key = keyOf(file); if (!key) return;
    const record = { path: key, method, at: now(), writeId: ++serial, ...context.getStore() };
    bounded(writes, key, record); emit('file-write', record);
  }
  function openFile(file, method) {
    const key = keyOf(file), prior = key && writes.get(key);
    if (!prior || now() < prior.at || now() - prior.at > 600000) return;
    const current = context.getStore();
    emit('write-then-open', { path: key, writeId: prior.writeId, writeMethod: prior.method, openMethod: method,
      channel: prior.channel, procedure: prior.procedure, sameIpcCall: !!current && current.ipcCall === prior.ipcCall,
      elapsedMs: now() - prior.at, frames: frames() });
  }
  function instrumentFiles(target = fs) {
    for (const method of ['writeFileSync', 'appendFileSync']) wrap(target, method, fn => function (file, ...args) {
      const result = fn.call(this, file, ...args); fileWrite(file, method); return result;
    });
    for (const method of ['writeFile', 'appendFile']) {
      wrap(target, method, fn => function (file, ...args) {
        const cb = args.at(-1);
        if (typeof cb === 'function') args[args.length - 1] = function (error, ...rest) {
          if (!error) fileWrite(file, method); return cb.call(this, error, ...rest);
        };
        return fn.call(this, file, ...args);
      });
      wrap(target.promises, method, fn => function (file, ...args) {
        const promise = fn.call(this, file, ...args);
        promise.then(() => fileWrite(file, `promises.${method}`), () => {}); return promise;
      });
    }
    wrap(target, 'createWriteStream', fn => function (file, ...args) {
      const stream = fn.call(this, file, ...args); stream.once('finish', () => fileWrite(file, 'createWriteStream')); return stream;
    });
  }
  function processPath(method, command, rest) {
    if (typeof command !== 'string' || /^(exec|execSync|fork)$/.test(method)) return {};
    const options = rest.find(value => value && typeof value === 'object' && !Array.isArray(value)) || {};
    const descriptor = Object.getOwnPropertyDescriptor(options, 'cwd');
    if (descriptor && !('value' in descriptor)) return {};
    const working = descriptor?.value instanceof URL ? require('node:url').fileURLToPath(descriptor.value) : descriptor?.value ? String(descriptor.value) : cwd();
    if (path.isAbsolute(command) || !/[\\/]/.test(command)) return {};
    const resolvedPath = path.resolve(working, command);
    return { relativePath: command, resolvedPath, workingDirectory: working, resolution: 'cwd-derived',
      exists: fs.existsSync(resolvedPath), ...context.getStore() };
  }
  return { observeModule, observeIpc, runIpc, navigation, instrumentFiles, openFile, processPath };
}
module.exports = { createPassiveEvidence, rpcMetadata, messageHosts };
