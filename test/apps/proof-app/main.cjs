'use strict';
const { app, BrowserWindow, session, ipcMain, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const hardened = process.env.ENG_PROOF_HARDENED === '1';
app.setPath('userData', process.env.ENG_PROOF_USER_DATA);
ipcMain.handle('read-canary', (event, file) => {
  if (hardened && !event.senderFrame.url.startsWith('https://trusted.example/')) throw Error('Foreign sender denied');
  return fs.readFileSync(file, 'utf8');
});
ipcMain.handle('open-link', (event, url) => {
  if (!hardened || /^https:\/\//i.test(url)) return shell.openExternal(url);
});
app.whenReady().then(() => {
  if (!hardened) session.defaultSession.setCertificateVerifyProc((request, callback) => callback(0));
  session.defaultSession.setPermissionRequestHandler((contents, permission, callback, details) => callback(!hardened || details.requestingUrl.startsWith('https://trusted.example/')));
  session.defaultSession.setPermissionCheckHandler((contents, permission, origin) => !hardened || origin === 'https://trusted.example');
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'"); res.end('<!doctype html><title>Tool proof fixture</title>');
  });
  server.listen(0, '127.0.0.1', () => {
    const win = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, preload: path.join(__dirname, 'preload.cjs') } });
    win.webContents.on('will-navigate', (event, url) => { if (hardened && !url.startsWith('https://trusted.example/')) event.preventDefault(); });
    win.webContents.setWindowOpenHandler(() => ({ action: hardened ? 'deny' : 'allow' }));
    win.loadURL(`http://127.0.0.1:${server.address().port}`);
    // A timed fixture gives the CLI long enough to finish native probes and port
    // inventory, then exits on its own. Production apps are driven by the tester.
    setTimeout(() => app.quit(), 16000);
  });
  app.on('will-quit', () => server.close());
});
