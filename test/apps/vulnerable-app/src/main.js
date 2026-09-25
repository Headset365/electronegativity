// Every classic Electron mistake, for the end-to-end tests. Do not copy.
const { app, BrowserWindow, ipcMain, shell, protocol, net, session } = require('electron');
const { exec } = require('child_process');
const path = require('path');

app.commandLine.appendSwitch('ignore-certificate-errors');

app.whenReady().then(() => {
  const win = new BrowserWindow({
    webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false, webviewTag: true, preload: path.join(__dirname, 'preload.js') }
  });
  win.loadURL('http://example.com');
  win.webContents.openDevTools();

  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => callback(true));
  session.defaultSession.setCertificateVerifyProc((request, callback) => callback(0));

  protocol.handle('app', (request) => net.fetch('file://' + path.join(__dirname, new URL(request.url).pathname)));

  win.webContents.on('will-navigate', (event, url) => console.log('navigating to', url));
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'allow' };
  });

  ipcMain.handle('run', (event, command) => exec(command));
  ipcMain.on('open', (event, file) => shell.openPath(file));
});

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  event.preventDefault();
  callback(true);
});
