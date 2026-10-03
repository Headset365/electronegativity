'use strict';
const { app, BrowserWindow, session, ipcMain, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const hardened = process.env.ENG_PROOF_HARDENED === '1';
app.setPath('userData', process.env.ENG_PROOF_USER_DATA);
ipcMain.handle('read-canary', (event, file) => {
  if (hardened && !event.senderFrame.url.startsWith('https://trusted.example/')) throw Error('Foreign sender denied');
  return fs.readFileSync(file, 'utf8');
});
ipcMain.handle('open-link', (event, url) => {
  if (!hardened || /^https:\/\//i.test(url)) return shell.openExternal(url);
});
ipcMain.handle('electron-trpc', async (event, message) => {
  if (message.method !== 'request' || message.operation.path !== 'files.saveFile') return;
  const file = path.join(app.getPath('userData'), 'passive-proof.txt');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, String(message.operation.input));
  // Observe the path handoff without launching an associated program. A missing
  // file makes openPath return an error; that result is not an opening proof.
  fs.unlinkSync(file);
  await shell.openPath(file);
  const child = spawn('./eng-proof-no-such-helper.exe'); child.on('error', () => {});
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
    win.webContents.setWindowOpenHandler(({ frameName }) => {
      if (frameName === 'eng-natural-preload') return { action: 'allow', overrideBrowserWindowOptions: { webPreferences: { preload: path.join(__dirname, 'preload.cjs') } } };
      if (frameName === 'eng-natural-default') return { action: 'allow' };
      return { action: hardened ? 'deny' : 'allow' };
    });
    win.webContents.once('did-finish-load', () => setTimeout(() => {
      void win.webContents.executeJavaScript(`window.fixture.save('${process.env.ELECTRONEGATIVITY_WATCH_MARKER || 'harmless'}'); window.open(location.href,'eng-natural-preload'); window.open(location.href,'eng-natural-default');`);
    }, 2000));
    win.loadURL(`http://127.0.0.1:${server.address().port}`);
    // A timed fixture gives the CLI long enough to finish native probes and port
    // inventory, then exits on its own. Production apps are driven by the tester.
    setTimeout(() => app.quit(), 16000);
  });
  app.on('will-quit', () => server.close());
});
