'use strict';
// A deliberately unsafe disposable editor, with its DevTools UI disabled.
const { app, BrowserWindow, WebContentsView, ipcMain } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const hardened = process.env.DEBUG_APP_HARDENED === '1';
const metrics = { outsideAllowed: false, insideAllowed: false, restored: false, navigationAllowed: false };
if (process.env.DEBUG_APP_PROBE_ROOT) ipcMain.handle('probe-read', (event,p) => {
  const allowed = path.join(process.env.DEBUG_APP_PROBE_ROOT,'allowed');
  const relative = typeof p === 'string' ? path.relative(allowed,path.resolve(p)) : '..';
  if (hardened && (!event.senderFrame || event.senderFrame !== event.sender.mainFrame || new URL(event.senderFrame.url).hostname !== '127.0.0.1' || relative.startsWith('..') || path.isAbsolute(relative))) throw Error('Rejected');
  const value = fs.readFileSync(p,'utf8');
  if (p === path.join(allowed,'inside.txt')) metrics.insideAllowed = true;
  if (p === path.join(process.env.DEBUG_APP_PROBE_ROOT,'outside.txt')) metrics.outsideAllowed = true;
  return value === 'tool-owned-canary';
});
const http = require('node:http');
if (process.env.DEBUG_APP_PROFILE) app.setPath('userData', process.env.DEBUG_APP_PROFILE);
let body = 'Hello', changed = false;
let seedOffered = false;
const server = http.createServer((req, res) => {
  if (req.method === 'PUT' && req.url === '/api/documents/42') {
    let text = '';
    req.on('data', chunk => { text += chunk; });
    req.on('end', () => {
      body = JSON.parse(text).body;
      if (body !== 'Hello') changed = true;
      res.end('{}');
      if (changed && body === 'Hello') { metrics.restored = true; }
      if (changed && body === 'Hello') setTimeout(() => app.quit(), 1500);
    });
  } else if (req.url === '/api/documents/42') {
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ body }));
  } else if (req.url === '/nav-probe') {
    res.setHeader('content-type','text/html');
    res.end(`<a id=probe href="/nav-target?ENG_LIVE_BENCHMARK">probe</a><script>setTimeout(()=>document.getElementById('probe').click(),500)</script>`);
  } else if (req.url.startsWith('/nav-target')) {
    res.end('tool-owned navigation target');
  } else {
    const seed = process.env.DEBUG_APP_AUTO_SAVE && !seedOffered;
    seedOffered = true;
    res.setHeader('content-type', 'text/html');
    res.end(`<!doctype html><body><button id="save">Save test record</button><div id="view"></div><script>
      fetch('/api/documents/42').then(r => r.json()).then(doc => { document.getElementById('view').${hardened ? 'textContent' : 'innerHTML'} = doc.body; });
      document.getElementById('save').onclick = () => fetch('/api/documents/42', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 42, body: 'Hello' }) });
      ${seed ? `setTimeout(() => document.getElementById("save").click(), ${Number(process.env.DEBUG_APP_SEED_DELAY || 1000)});` : ''}
      ${process.env.DEBUG_APP_PROBE_ROOT ? `Promise.allSettled([window.probe.read(${JSON.stringify(path.join(process.env.DEBUG_APP_PROBE_ROOT,'allowed','inside.txt'))}),window.probe.read(${JSON.stringify(path.join(process.env.DEBUG_APP_PROBE_ROOT,'outside.txt'))})]);` : ''}
    </script></body>`);
  }
});
app.whenReady().then(() => {
  server.listen(Number(process.env.DEBUG_APP_PORT || 0), '127.0.0.1', () => {
    const win = new BrowserWindow({ show: false, webPreferences: { devTools: false, contextIsolation: true, sandbox: true, nodeIntegration: false, ...(process.env.DEBUG_APP_PROBE_ROOT ? {preload:path.join(__dirname,'benchmark-preload.cjs')} : {}) } });
    let target = win.webContents;
    if (process.env.DEBUG_APP_EMBEDDED_VIEW) {
      const view = new WebContentsView({ webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } });
      win.contentView.addChildView(view); view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
      target = view.webContents;
    }
    if (process.env.DEBUG_APP_PROBE_ROOT) {
      const navigation = new BrowserWindow({show:false,webPreferences:{contextIsolation:true,sandbox:true}});
      navigation.webContents.on('will-navigate',event=>{ if(hardened) event.preventDefault(); });
      navigation.webContents.on('did-navigate',(_event,url)=>{if(url.includes('/nav-target'))metrics.navigationAllowed=true;});
      navigation.loadURL(`http://127.0.0.1:${server.address().port}/nav-probe`);
    }
    target.loadURL(`http://127.0.0.1:${server.address().port}/view`);
    if (process.env.DEBUG_APP_EXTRA_WINDOW) {
      const other = new BrowserWindow({ show: false, webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } });
      other.loadURL('data:text/html,Other app window');
    }
  });
});
app.on('will-quit', () => { if(process.env.DEBUG_APP_PROBE_ROOT) fs.writeFileSync(path.join(process.env.DEBUG_APP_PROBE_ROOT,'metrics.json'),JSON.stringify(metrics)); server.close(); });
setTimeout(() => app.quit(), 100000);
