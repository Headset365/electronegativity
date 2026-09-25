// An app following every recommendation of https://www.electronjs.org/docs/latest/tutorial/security
import { app, BrowserWindow, ipcMain, net, protocol, session, shell } from 'electron';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const APP_ORIGIN = 'app://bundle';
const RENDERER_ROOT = path.join(import.meta.dirname, '../renderer');
const TRUSTED_EXTERNAL_HOSTS = new Set(['docs.example.com', 'github.com']);

// #18: serve the UI from a custom protocol instead of file://
protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } }]);

function isTrustedSender(frame) {
  return frame && new URL(frame.url).origin === APP_ORIGIN;
}

function openExternalSafely(url) {
  const parsed = new URL(url);
  if (parsed.protocol === 'https:' && TRUSTED_EXTERNAL_HOSTS.has(parsed.hostname)) {
    shell.openExternal(parsed.toString());
  }
}

app.whenReady().then(() => {
  protocol.handle('app', (request) => {
    const filePath = path.resolve(RENDERER_ROOT, decodeURIComponent(new URL(request.url).pathname).slice(1));
    if (!filePath.startsWith(RENDERER_ROOT + path.sep)) return new Response('Forbidden', { status: 403 });
    return net.fetch(pathToFileURL(filePath).toString());
  });

  // #5: permissions are only granted to the app itself
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(new URL(webContents.getURL()).origin === APP_ORIGIN && permission === 'notifications');
  });
  session.defaultSession.setPermissionCheckHandler((webContents, permission, requestingOrigin) => {
    return requestingOrigin === APP_ORIGIN && permission === 'notifications';
  });

  // #17: every IPC handler validates the sender
  ipcMain.handle('get-version', (event) => {
    if (!isTrustedSender(event.senderFrame)) throw new Error('untrusted sender');
    return app.getVersion();
  });

  // #2, #3, #4: no Node.js, isolated and sandboxed renderers (the defaults)
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: { preload: path.join(import.meta.dirname, '../preload/index.mjs') }
  });
  win.loadURL(`${APP_ORIGIN}/index.html`);
});

// #13, #14: no navigation, new windows only for trusted external links
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (navigationEvent) => navigationEvent.preventDefault());
  contents.setWindowOpenHandler(({ url }) => {
    openExternalSafely(url);
    return { action: 'deny' };
  });
});
