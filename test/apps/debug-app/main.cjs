'use strict';
// A deliberately unsafe disposable editor, with its DevTools UI disabled.
const { app, BrowserWindow, WebContentsView } = require('electron');
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
      if (changed && body === 'Hello') setTimeout(() => app.quit(), 1500);
    });
  } else if (req.url === '/api/documents/42') {
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ body }));
  } else {
    const seed = process.env.DEBUG_APP_AUTO_SAVE && !seedOffered;
    seedOffered = true;
    res.setHeader('content-type', 'text/html');
    res.end(`<!doctype html><body><button id="save">Save test record</button><div id="view"></div><script>
      fetch('/api/documents/42').then(r => r.json()).then(doc => { document.getElementById('view').innerHTML = doc.body; });
      document.getElementById('save').onclick = () => fetch('/api/documents/42', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 42, body: 'Hello' }) });
      ${seed ? 'setTimeout(() => document.getElementById("save").click(), 1000);' : ''}
    </script></body>`);
  }
});
app.whenReady().then(() => {
  server.listen(Number(process.env.DEBUG_APP_PORT || 0), '127.0.0.1', () => {
    const win = new BrowserWindow({ show: false, webPreferences: { devTools: false, contextIsolation: true, sandbox: true, nodeIntegration: false } });
    let target = win.webContents;
    if (process.env.DEBUG_APP_EMBEDDED_VIEW) {
      const view = new WebContentsView({ webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } });
      win.contentView.addChildView(view); view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
      target = view.webContents;
    }
    target.loadURL(`http://127.0.0.1:${server.address().port}/view`);
    if (process.env.DEBUG_APP_EXTRA_WINDOW) {
      const other = new BrowserWindow({ show: false, webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } });
      other.loadURL('data:text/html,Other app window');
    }
  });
});
app.on('will-quit', () => server.close());
setTimeout(() => app.quit(), 100000);
