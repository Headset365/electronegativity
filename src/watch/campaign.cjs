'use strict';
// Bounded, opt-in tests delivered through the application's own HTTP session. Every case has a unique
// renderer signal. A successful HTTP response alone is never interpreted as execution or a safe result.
const CASES = ['text', 'html', 'event-handler', 'script-tag', 'svg-handler', 'javascript-url', 'node', 'electron', 'fs-read', 'eval',
  'null', 'boolean', 'number', 'array', 'object', 'empty', 'long',
  'cookie-canary', 'localstorage-canary', 'indexeddb-canary',
  'external-image', 'external-svg', 'external-script', 'external-frame', 'external-stylesheet', 'external-font', 'external-media', 'redirect-image',
  'nav-loopback', 'nav-redirect', 'nav-data',
  'api-normal', 'api-null', 'api-number', 'api-array', 'api-object', 'api-traversal', 'api-absolute', 'api-unc', 'api-file-url', 'api-https-url', 'api-loopback-url'];
const EXECUTION = new Set(['event-handler', 'script-tag', 'svg-handler', 'javascript-url', 'node', 'electron', 'fs-read', 'eval', 'external-script']);
const RESOURCES = new Set(CASES.filter(name => name.startsWith('external-') || name === 'redirect-image'));
RESOURCES.add('api-loopback-url');
RESOURCES.add('nav-loopback'); RESOURCES.add('nav-redirect');
const API = new Set(CASES.filter(name => name.startsWith('api-')));
API.forEach(name => EXECUTION.add(name));
const TYPED = new Set(['null', 'boolean', 'number', 'array', 'object']);
const DATA = new Set(['cookie-canary', 'localstorage-canary', 'indexeddb-canary']);
DATA.forEach(name => EXECUTION.add(name));

function attr(code) { return code.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;'); }
// Only string leaves are candidates. Skip fields whose names suggest identities, credentials or control flags;
// the original request body is restored after the bounded campaign. Explicit `fields` can override this filter.
function discoverFields(body) {
  const excluded = new Set(['id', 'ids', 'uuid', 'key', 'token', 'password', 'secret', 'auth', 'csrf', 'nonce', 'version', 'type', 'role',
    'permission', 'status', 'callback', 'url', 'href', 'src', 'path', 'mode', 'format', 'lang', 'locale', 'sort', 'order', 'app']);
  const out = [];
  // a value that identifies a record rather than holding content: 20261002150519-mc4r8gp, y6hpRYzH31hk, a UUID
  const identifier = value => /^[A-Za-z0-9_-]{6,64}$/.test(value) && /\d/.test(value) && /[A-Za-z]/.test(value) || /^\d{4,}$/.test(value);
  const add = (name, value) => {
    // camelCase names split too: rootID, dataType, noteId
    const parts = name.replace(/([a-z0-9])([A-Z])/g, '$1.$2').toLowerCase().replaceAll('[]', '.').split(/[._-]/);
    if (typeof value === 'string' && name && !parts.some(part => excluded.has(part) || /(?:token|password|secret|csrf|nonce)$/.test(part)) &&
      !identifier(value) && value.length <= 10000 && !out.includes(name) && out.length < 8) out.push(name);
  };
  const walk = (value, name, depth) => {
    if (depth > 6 || out.length >= 8) return;
    if (Array.isArray(value)) value.slice(0, 20).forEach(item => walk(item, `${name}[]`, depth + 1));
    else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) walk(item, name ? `${name}.${key}` : key, depth + 1);
    else add(name || '(body)', value);
  };
  const trimmed = String(body || '').trim();
  if (/^[[{]/.test(trimmed)) {
    try { walk(JSON.parse(trimmed), '', 0); } catch { return []; }
  } else if (/^[\w.%[\]-]+=/.test(trimmed) && !/\s/.test(trimmed.slice(0, 200))) {
    for (const [name, value] of new URLSearchParams(trimmed)) add(name, value);
  }
  return out;
}
function valueFor(name, marker, canary) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(marker || '') || !CASES.includes(name)) throw new Error('Invalid campaign marker or case');
  const slot = canary?.slot;
  if (slot !== undefined && (!Number.isInteger(slot) || slot < 0 || slot > 7)) throw new Error('Invalid field slot');
  const suffix = slot === undefined ? '' : `:${slot}`;
  const log = (result) => `console.log(${JSON.stringify(`ENG_CAMPAIGN:${marker}:${name}${suffix}:${result}`)})`;
  const img = code => `<img src="data:,${marker}" onerror="${attr(code)}" alt="">`;
  const url = resource => {
    if (!canary?.resourceBase || !/^http:\/\/127\.0\.0\.1:\d+$/.test(canary.resourceBase)) throw new Error('Local resource receiver is required');
    return `${canary.resourceBase}/${resource}/${marker}${slot === undefined ? '' : `/${slot}`}`;
  };
  if (API.has(name)) {
    const api = canary?.api;
    if (!api || !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,4}$/.test(api.path || '') || !Array.isArray(api.args) ||
      !Number.isInteger(api.mutationIndex) || api.mutationIndex < 0 || api.mutationIndex >= api.args.length) throw new Error('An explicit API contract is required');
    const args = JSON.parse(JSON.stringify(api.args));
    const replacements = { 'api-null': null, 'api-number': 0, 'api-array': [marker], 'api-object': { probe: marker },
      'api-traversal': `../${marker}.txt`, 'api-unc': `\\\\127.0.0.1\\eng-probe\\${marker}.txt`,
      'api-https-url': `https://example.invalid/${marker}` };
    if (name === 'api-absolute' || name === 'api-file-url') {
      if (!canary.path) throw new Error('A tool-owned file path is required');
      replacements['api-absolute'] = canary.path;
      replacements['api-file-url'] = `file:///${canary.path.replace(/\\/g, '/').replace(/^\//, '')}`;
    }
    if (name === 'api-loopback-url') replacements[name] = url('api');
    if (name !== 'api-normal') {
      if (api.mutationPath) {
        if (!Array.isArray(api.mutationPath) || !api.mutationPath.length || api.mutationPath.length > 6 || api.mutationPath.some(key => !/^[\w$-]{1,80}$/.test(key) || ['__proto__', 'prototype', 'constructor'].includes(key))) throw new Error('Invalid API mutation path');
        let target = args[api.mutationIndex];
        for (const key of api.mutationPath.slice(0, -1)) target = target?.[key];
        const key = api.mutationPath.at(-1);
        if (!target || typeof target !== 'object' || !Object.hasOwn(target, key)) throw new Error('API mutation field is absent');
        target[key] = replacements[name];
      } else args[api.mutationIndex] = replacements[name];
    }
    const code = `try { ${log('executed')}; var target = window, owner = window; for (var k of ${JSON.stringify(api.path.split('.'))}) { owner = target; target = target && target[k]; } if (typeof target !== "function") ${log('api-unavailable')}; else { ${log('api-invoked')}; Promise.resolve(target.apply(owner, ${JSON.stringify(args)})).then(() => ${log('api-resolved')}, () => ${log('api-rejected')}); } } catch(e) { ${log('api-rejected')}; }`;
    return img(code);
  }
  if (DATA.has(name)) {
    const data = canary?.data;
    if (!data || !/^eng_campaign_[A-Za-z0-9_-]{8,140}$/.test(data.name || '') || !/^[a-f0-9]{32}$/.test(data.value || ''))
      throw new Error('Controlled renderer data canary is required');
    const signal = kind => log(`${kind}-canary-read`);
    let code;
    if (name === 'cookie-canary') code = `try { ${log('executed')}; if (document.cookie.split(';').some(x => x.trim() === ${JSON.stringify(`${data.name}=${data.value}`)})) ${signal('cookie')}; else ${log('canary-unverified')}; } catch(e) { ${log('canary-unverified')}; }`;
    else if (name === 'localstorage-canary') code = `try { ${log('executed')}; if (localStorage.getItem(${JSON.stringify(data.name)}) === ${JSON.stringify(data.value)}) ${signal('localstorage')}; else ${log('canary-unverified')}; } catch(e) { ${log('canary-unverified')}; }`;
    else code = `try { ${log('executed')}; var r = indexedDB.open(${JSON.stringify(data.name)}); r.onerror = () => ${log('canary-unverified')}; r.onsuccess = () => { var db = r.result; try { var g = db.transaction('canary').objectStore('canary').get('nonce'); g.onsuccess = () => { if (g.result === ${JSON.stringify(data.value)}) ${signal('indexeddb')}; else ${log('canary-unverified')}; db.close(); }; g.onerror = () => { ${log('canary-unverified')}; db.close(); }; } catch(e) { ${log('canary-unverified')}; db.close(); } }; } catch(e) { ${log('canary-unverified')}; }`;
    return img(code);
  }
  switch (name) {
    case 'text': return marker;
    case 'html': return `<span data-${marker}="1">${marker}</span>`;
    case 'event-handler': return img(log('executed'));
    case 'script-tag': return `<script>${log('executed')}</script>`;
    case 'svg-handler': return `<svg onload="${attr(log('executed'))}"></svg>`;
    case 'javascript-url': return `<a href="javascript:${attr(log('executed'))}" data-eng-campaign="${marker}">probe</a>`;
    case 'node': return img(`try { ${log('executed')}; if (typeof require === "function" && typeof process === "object" && !!process.versions?.electron) ${log('node-available')}; else ${log('node-unverified')}; } catch(e) { ${log('node-unverified')}; }`);
    case 'electron': return img(`try { ${log('executed')}; if (typeof require === "function" && !!require("electron")?.ipcRenderer) ${log('electron-available')}; else ${log('electron-unverified')}; } catch(e) { ${log('electron-unverified')}; }`);
    case 'fs-read': {
      if (!canary || !canary.path || !canary.value) throw new Error('Filesystem canary is required');
      const code = `try { ${log('executed')}; var f = typeof require === "function" ? require("fs") : null; if (f && f.readFileSync(${JSON.stringify(canary.path)}, "utf8") === ${JSON.stringify(canary.value)}) ${log('fs-read')}; else ${log('fs-unverified')}; } catch(e) { ${log('fs-unverified')}; }`;
      return img(code);
    }
    case 'eval': return img(`try { ${log('executed')}; if (eval("1+1") === 2) ${log('eval-allowed')}; } catch(e) { ${log('eval-blocked')}; }`);
    case 'null': return null;
    case 'boolean': return false;
    case 'number': return 0;
    case 'array': return [marker];
    case 'object': return { probe: marker };
    case 'empty': return '';
    case 'long': return marker.repeat(Math.ceil(2048 / marker.length)).slice(0, 2048);
    case 'external-image': return `<img src="${url('image')}" alt="">`;
    case 'external-svg': return `<img src="${url('svg')}" alt="">`;
    case 'external-script': return `<script src="${url('script')}"></script>`;
    case 'external-frame': return `<iframe src="${url('frame')}"></iframe>`;
    case 'external-stylesheet': return `<link rel="stylesheet" href="${url('stylesheet')}">`;
    case 'external-font': return `<style>@font-face{font-family:engprobe;src:url("${url('font')}")} .engprobe{font-family:engprobe}</style><span class="engprobe">probe</span>`;
    case 'external-media': return `<audio preload="auto" src="${url('media')}"></audio>`;
    case 'redirect-image': return `<img src="${url('redirect')}" alt="">`;
    case 'nav-loopback': return `<a href="${url('navigation')}" data-eng-campaign="${marker}">benign navigation probe</a>`;
    case 'nav-redirect': return `<a href="${url('navigation-redirect')}" data-eng-campaign="${marker}">benign redirect probe</a>`;
    case 'nav-data': return `<a href="data:text/html,${encodeURIComponent(`<title>${marker}</title><p>Benign navigation probe</p>`)}" data-eng-campaign="${marker}">benign data URL probe</a>`;
    default: throw new Error('Unknown campaign case');
  }
}

async function runCampaign({ profile, marker, campaignId, fetch, fill, view, write, canary, seed, signal, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const { verifySaved } = require('./campaign_verify.cjs');
  const output = write;
  write = (kind, data) => output(kind, { ...(campaignId ? { campaignId } : {}), ...data });
  const { request, cases, waitMs } = profile;
  const fields = profile.fields === 'auto' ? discoverFields(request.body) : (profile.fields || [profile.field]);
  if (!fields.length) throw new Error('No mutable string fields were discovered in the configured request');
  write('campaign-fields', { count: fields.length, automatic: profile.fields === 'auto' });
  let sent = 0;
  let failed = 0;
  let firstError;
  let contentType;
  try {
    for (const [slot, field] of fields.entries()) for (const name of cases) {
      if (signal?.aborted) throw new Error('Campaign cancelled before completion; restoration may be incomplete');
      let fixture;
      try {
        fixture = name === 'fs-read' || name === 'api-absolute' || name === 'api-file-url' ? canary() : undefined;
        const fieldSlot = fields.length > 1 ? slot : undefined;
        const data = DATA.has(name) ? await seed(name, fieldSlot) : undefined;
        if (DATA.has(name)) write('campaign-seed', { case: name, slot: fieldSlot, ok: !!data });
        const value = valueFor(name, marker, { ...(fixture || {}), resourceBase: profile.resourceBase, api: profile.api, slot: fieldSlot, data });
        const built = fill(request.body, marker, [{ name: field, html: true }], false, value);
        if (!built) throw new Error('field is absent, not a string, or body cannot be rebuilt');
        if (TYPED.has(name) && built.contentType !== 'application/json') throw new Error('Typed mutation requires a JSON request body');
        contentType = built.contentType;
        const headers = { ...request.headers, 'content-type': built.contentType };
        const response = await fetch(request.url, { method: request.method, headers, body: built.body });
        // only a request the server answered can have changed the record: that is what restoration undoes
        sent++;
        write('campaign-send', { case: name, route: profile.route, status: response.status, ok: !!response.ok, field, slot: fieldSlot });
        if (response.ok && profile.verify) write('campaign-verification', { case: name, slot: fieldSlot,
          ...await verifySaved({ verify: profile.verify, expected: built.body, fields: [field], fetch, headers: request.headers }) });
        if (response.ok && view) {
          const opened = await view(name, fieldSlot);
          write('campaign-view', { case: name, slot: fieldSlot, opened: !!opened });
        }
      } catch (error) {
        failed++;
        if (!firstError) firstError = String(error && error.message || error).slice(0, 160);
        write('campaign-send', { case: name, route: profile.route, field, slot: fields.length > 1 ? slot : undefined,
          ok: false, error: String(error && error.message || error).slice(0, 160) });
      }
      await delay(waitMs);
    }
  } finally {
    if (profile.restoreOnDone !== false && sent) {
      try {
        const response = await fetch(request.url, { method: request.method,
          headers: { ...request.headers, 'content-type': contentType }, body: request.body });
        write('campaign-restore', { ok: !!response.ok, status: response.status,
          ...await verifySaved({ verify: response.ok && profile.verify, expected: request.body, fields, fetch, headers: request.headers }) });
      } catch (error) {
        write('campaign-restore', { ok: false, error: String(error && error.message || error).slice(0, 160) });
      }
    }
  }
  write('campaign-done', { cases: cases.length * fields.length, fields: fields.length, delivered: sent, failed, ...(firstError ? { error: firstError } : {}) });
}

async function startResourceReceiver(marker, write) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(marker || '')) throw new Error('Invalid resource marker');
  const server = require('http').createServer((req, res) => {
    const resource = new URL(req.url, 'http://127.0.0.1').pathname.match(/^\/(image|svg|script|frame|stylesheet|font|media|redirect|api|docx|navigation|navigation-redirect)\/([A-Za-z0-9_-]+)(?:\/([0-7]))?$/);
    if (!resource || resource[2] !== marker || req.method !== 'GET') { res.writeHead(404); res.end(); return; }
    const kind = resource[1];
    if (kind === 'docx') {
      write('docx-resource', { case: 'external-relationship', resource: 'loopback', cookiePresent: !!req.headers.cookie,
        authorizationPresent: !!req.headers.authorization });
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' }); res.end('benign DOCX relationship');
      return;
    }
    if (kind === 'navigation' || kind === 'navigation-redirect') {
      const slot = resource[3] === undefined ? undefined : Number(resource[3]);
      const caseName = kind === 'navigation-redirect' || req.url.includes('via=redirect') ? 'nav-redirect' : 'nav-loopback';
      write('campaign-resource', { case: caseName, slot, resource: kind, cookiePresent: !!req.headers.cookie,
        authorizationPresent: !!req.headers.authorization });
      if (kind === 'navigation-redirect') { res.writeHead(302, { location: `/navigation/${marker}${slot === undefined ? '' : `/${slot}`}?via=redirect` }); res.end(); }
      else { res.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' }); res.end('<!doctype html><title>Benign navigation destination</title>'); }
      return;
    }
    const caseName = kind === 'redirect' || req.url.includes('via=redirect') ? 'redirect-image' : kind === 'api' ? 'api-loopback-url' : `external-${kind}`;
    const slot = resource[3] === undefined ? undefined : Number(resource[3]);
    write('campaign-resource', { case: caseName, slot, resource: kind, cookiePresent: !!req.headers.cookie, authorizationPresent: !!req.headers.authorization });
    if (kind === 'redirect') { res.writeHead(302, { location: `/image/${marker}${slot === undefined ? '' : `/${slot}`}?via=redirect` }); res.end(); return; }
    const content = kind === 'script' ? ['text/javascript', `console.log(${JSON.stringify(`ENG_CAMPAIGN:${marker}:external-script${slot === undefined ? '' : `:${slot}`}:executed`)})`] :
      kind === 'svg' ? ['image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'] :
        kind === 'frame' ? ['text/html', '<!doctype html><title>benign probe frame</title>'] :
          kind === 'stylesheet' ? ['text/css', 'body { --eng-probe: 1 }'] :
            kind === 'font' ? ['font/woff2', ''] : kind === 'media' ? ['audio/wav', ''] :
              kind === 'api' ? ['text/plain', 'benign test receiver'] :
                ['image/png', Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/mXcAAAAASUVORK5CYII=', 'base64')];
    res.writeHead(200, { 'content-type': content[0], 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
    res.end(content[1]);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

module.exports = { CASES, EXECUTION, RESOURCES, API, DATA, valueFor, discoverFields, runCampaign, startResourceReceiver };
