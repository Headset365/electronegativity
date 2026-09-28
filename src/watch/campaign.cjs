'use strict';
// Bounded, opt-in tests delivered through the application's own HTTP session. Every case has a unique
// renderer signal. A successful HTTP response alone is never interpreted as execution or a safe result.
const CASES = ['text', 'html', 'event-handler', 'script-tag', 'svg-handler', 'javascript-url', 'node', 'electron', 'fs-read', 'eval',
  'null', 'boolean', 'number', 'array', 'object', 'empty', 'long',
  'external-image', 'external-svg', 'external-script', 'external-frame', 'external-stylesheet', 'external-font', 'external-media', 'redirect-image',
  'api-normal', 'api-null', 'api-number', 'api-array', 'api-object', 'api-traversal', 'api-absolute', 'api-unc', 'api-file-url', 'api-https-url'];
const EXECUTION = new Set(['event-handler', 'script-tag', 'svg-handler', 'javascript-url', 'node', 'electron', 'fs-read', 'eval', 'external-script']);
const RESOURCES = new Set(CASES.filter(name => name.startsWith('external-') || name === 'redirect-image'));
const API = new Set(CASES.filter(name => name.startsWith('api-')));
API.forEach(name => EXECUTION.add(name));
const TYPED = new Set(['null', 'boolean', 'number', 'array', 'object']);

function attr(code) { return code.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;'); }
function valueFor(name, marker, canary) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(marker || '') || !CASES.includes(name)) throw new Error('Invalid campaign marker or case');
  const log = (result) => `console.log(${JSON.stringify(`ENG_CAMPAIGN:${marker}:${name}:${result}`)})`;
  const img = code => `<img src="data:,${marker}" onerror="${attr(code)}" alt="">`;
  const url = resource => {
    if (!canary?.resourceBase || !/^http:\/\/127\.0\.0\.1:\d+$/.test(canary.resourceBase)) throw new Error('Local resource receiver is required');
    return `${canary.resourceBase}/${resource}/${marker}`;
  };
  if (API.has(name)) {
    const api = canary?.api;
    if (!api || !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,4}$/.test(api.path || '') || !Array.isArray(api.args) ||
      !Number.isInteger(api.mutationIndex) || api.mutationIndex < 0 || api.mutationIndex >= api.args.length) throw new Error('An explicit API contract is required');
    const args = [...api.args];
    const replacements = { 'api-null': null, 'api-number': 0, 'api-array': [marker], 'api-object': { probe: marker },
      'api-traversal': `../${marker}.txt`, 'api-unc': `\\\\127.0.0.1\\eng-probe\\${marker}.txt`,
      'api-https-url': `https://example.invalid/${marker}` };
    if (name === 'api-absolute' || name === 'api-file-url') {
      if (!canary.path) throw new Error('A tool-owned file path is required');
      replacements['api-absolute'] = canary.path;
      replacements['api-file-url'] = `file:///${canary.path.replace(/\\/g, '/').replace(/^\//, '')}`;
    }
    if (name !== 'api-normal') args[api.mutationIndex] = replacements[name];
    const code = `try { ${log('executed')}; var target = window, owner = window; for (var k of ${JSON.stringify(api.path.split('.'))}) { owner = target; target = target && target[k]; } if (typeof target !== "function") ${log('api-unavailable')}; else { ${log('api-invoked')}; Promise.resolve(target.apply(owner, ${JSON.stringify(args)})).then(() => ${log('api-resolved')}, () => ${log('api-rejected')}); } } catch(e) { ${log('api-rejected')}; }`;
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
    default: throw new Error('Unknown campaign case');
  }
}

async function runCampaign({ profile, marker, fetch, fill, view, write, canary, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const { request, field, cases, waitMs } = profile;
  let sent = 0;
  let contentType;
  for (const name of cases) {
    let fixture;
    try {
      fixture = name === 'fs-read' || name === 'api-absolute' || name === 'api-file-url' ? canary() : undefined;
      const value = valueFor(name, marker, { ...(fixture || {}), resourceBase: profile.resourceBase, api: profile.api });
      const built = fill(request.body, marker, [{ name: field, html: true }], false, value);
      if (!built) throw new Error('field is absent, not a string, or body cannot be rebuilt');
      if (TYPED.has(name) && built.contentType !== 'application/json') throw new Error('Typed mutation requires a JSON request body');
      contentType = built.contentType;
      const headers = { ...request.headers, 'content-type': built.contentType };
      sent++;
      const response = await fetch(request.url, { method: request.method, headers, body: built.body });
      write('campaign-send', { case: name, route: profile.route, status: response.status, ok: !!response.ok, field });
      if (response.ok && view) {
        const opened = await view(name);
        write('campaign-view', { case: name, opened: !!opened });
      }
    } catch (error) {
      write('campaign-send', { case: name, route: profile.route, ok: false, error: String(error && error.message || error).slice(0, 160) });
    }
    await delay(waitMs);
  }
  if (profile.restoreOnDone !== false && sent) {
    try {
      const response = await fetch(request.url, { method: request.method,
        headers: { ...request.headers, 'content-type': contentType }, body: request.body });
      write('campaign-restore', { ok: !!response.ok, status: response.status });
    } catch (error) {
      write('campaign-restore', { ok: false, error: String(error && error.message || error).slice(0, 160) });
    }
  }
  write('campaign-done', { cases: cases.length });
}

async function startResourceReceiver(marker, write) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(marker || '')) throw new Error('Invalid resource marker');
  const server = require('http').createServer((req, res) => {
    const resource = new URL(req.url, 'http://127.0.0.1').pathname.match(/^\/(image|svg|script|frame|stylesheet|font|media|redirect)\/([A-Za-z0-9_-]+)$/);
    if (!resource || resource[2] !== marker || req.method !== 'GET') { res.writeHead(404); res.end(); return; }
    const kind = resource[1];
    const caseName = kind === 'redirect' || req.url.includes('via=redirect') ? 'redirect-image' : `external-${kind}`;
    write('campaign-resource', { case: caseName, resource: kind, cookiePresent: !!req.headers.cookie, authorizationPresent: !!req.headers.authorization });
    if (kind === 'redirect') { res.writeHead(302, { location: `/image/${marker}?via=redirect` }); res.end(); return; }
    const content = kind === 'script' ? ['text/javascript', `console.log(${JSON.stringify(`ENG_CAMPAIGN:${marker}:external-script:executed`)})`] :
      kind === 'svg' ? ['image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'] :
        kind === 'frame' ? ['text/html', '<!doctype html><title>benign probe frame</title>'] :
          kind === 'stylesheet' ? ['text/css', 'body { --eng-probe: 1 }'] :
            kind === 'font' ? ['font/woff2', ''] : kind === 'media' ? ['audio/wav', ''] :
              ['image/png', Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/mXcAAAAASUVORK5CYII=', 'base64')];
    res.writeHead(200, { 'content-type': content[0], 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
    res.end(content[1]);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

module.exports = { CASES, EXECUTION, RESOURCES, API, valueFor, runCampaign, startResourceReceiver };
