// Test application for watch mode: it opens windows with different settings, uses IPC, requests a permission and
// quits by itself, standing in for a user clicking through an app.
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const http = require('http');
const path = require('path');

ipcMain.handle('documents:get', (event, id) => ({ id, title: 'Quarterly report' }));
ipcMain.handle('documents:delete', () => true); // registered but never called: shows up in the coverage report
ipcMain.on('log', () => {});

app.whenReady().then(async () => {
  // a local server standing in for the app's backend, sending a CSP header
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
    response.end('<!doctype html><title>Remote</title><p>Remote page</p>');
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const remote = `http://127.0.0.1:${server.address().port}/viewer?token=secret`;

  // an editor window with Node.js access and no CSP
  const editor = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false } });
  await editor.loadFile(path.join(__dirname, 'editor.html'));

  // a hardened window loading the backend page
  const viewer = new BrowserWindow({ show: false, webPreferences: { preload: path.join(__dirname, 'preload.js'), sandbox: true } });
  await viewer.loadURL(remote);
  await viewer.webContents.executeJavaScript('window.app.getDocument(7).then(() => window.app.log("opened"))');
  await editor.webContents.executeJavaScript('Notification.requestPermission()').catch(() => {});

  shell.openExternal('mailto:support@example.com').catch(() => {});
  setTimeout(() => { server.close(); app.quit(); }, 1500);
});
