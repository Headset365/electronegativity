// Test application for watch mode: it opens windows with different settings, uses IPC, requests a permission and
// quits by itself, standing in for a user clicking through an app.
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const http = require('http');
const path = require('path');
const os = require('os');
// the marker the tester plants (watch mode passes it to the hook): here the server's stored document carries it, and the
// app is driven through the ways content moves (a save request, a link, a window.open, IPC, a file path)
const MARKER = process.env.ELECTRONEGATIVITY_WATCH_MARKER || 'ENGNONE';
require('./ENGCANARY-module.cjs');

ipcMain.handle('documents:get', (event, id) => ({ id, title: 'Quarterly report' }));
ipcMain.handle('documents:delete', () => true); // registered but never called: shows up in the coverage report
ipcMain.on('log', () => {});

app.whenReady().then(async () => {
  // a local server standing in for the app's backend, sending a CSP header. Its page runs a minified script whose source
  // map carries the original code (captured for the static scan), and saves a document with HTML in it through the API.
  const viewerSource = "fetch('/api/documents/42').then(res => res.json()).then(doc => { document.getElementById('doc').innerHTML = doc.body; });";
  const saveSource = "fetch('/api/documents/42', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ body: '<p>Quarterly <b>report</b></p>' }) });";
  const map = JSON.stringify({ version: 3, file: 'viewer.js', mappings: 'AAAA', names: [], sources: ['webpack://app/./src/viewer.js', 'webpack://app/./src/save.js'], sourcesContent: [viewerSource, saveSource] });
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
    const url = request.url.split('?')[0];
    if (url === '/static/viewer.js') {
      response.setHeader('content-type', 'application/javascript');
      return response.end(`${viewerSource.replace(/\s+/g, ' ')}${saveSource}\n//# sourceMappingURL=viewer.js.map`);
    }
    if (url === '/static/viewer.js.map') return response.end(map);
    if (url.startsWith('/api/documents/')) {
      request.resume();
      response.setHeader('content-type', 'application/json');
      return response.end(JSON.stringify({ id: 42, body: `<p>Quarterly report <span data-${MARKER}="1">${MARKER}</span></p>` }));
    }
    response.end('<!doctype html><title>Remote</title><p>Remote page</p><div id="doc"></div><script src="/static/viewer.js"></script>');
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const remote = `http://127.0.0.1:${server.address().port}/viewer?token=secret`;

  // an editor window with Node.js access and no CSP
  const editor = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false } });
  await editor.loadFile(path.join(__dirname, 'editor.html'));

  // a hardened window loading the backend page
  const viewer = new BrowserWindow({ show: false, webPreferences: { preload: path.join(__dirname, 'preload.js'), sandbox: true } });
  await viewer.loadURL(remote);
  viewer.webContents.on('will-navigate', (event) => event.preventDefault());
  viewer.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  await viewer.webContents.executeJavaScript('window.app.getDocument(7).then(() => window.app.log("opened"))');
  // the tester saves content carrying the marker, clicks a link carrying it (blocked), and the page passes it over IPC
  await viewer.webContents.executeJavaScript(`fetch('/api/documents/42', { method: 'PUT', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: '${MARKER}', body: '<span data-${MARKER}="1">${MARKER}</span>' }) }).then(r => r.text())`);
  await viewer.webContents.executeJavaScript(`window.open('https://example.invalid/${MARKER}'); window.app.log('${MARKER}'); location.href = 'https://example.invalid/${MARKER}'; 1`);
  // an attachment whose name came from content, opened with its default program (it doesn't exist: nothing opens)
  shell.openPath(path.join(os.tmpdir(), `${MARKER}-missing-attachment.txt`)).catch(() => {});
  await editor.webContents.executeJavaScript('Notification.requestPermission()').catch(() => {});
  // the user pastes formatted content into the editor
  await editor.webContents.executeJavaScript(`(() => { const data = new DataTransfer(); data.setData('text/html', '<b>pasted</b>');
    document.querySelector('[contenteditable]').dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true })); })()`);

  // a document view showing stored text safely (escaped), with the same preload as the viewer
  const documentView = new BrowserWindow({ show: false, webPreferences: { preload: path.join(__dirname, 'preload.js'), sandbox: true } });
  await documentView.loadFile(path.join(__dirname, 'safe-view.html'));

  shell.openExternal('mailto:support@example.com').catch(() => {});
  setTimeout(() => { server.close(); app.quit(); }, 2500);
});
