import { ipcMain, ipcRenderer } from 'electron';

function validateSender(frame) {
  return new URL(frame.url).host === 'app.local';
}

ipcMain.handle('get-secrets', (event) => {
  if (!validateSender(event.senderFrame)) return null;
  return 'secret';
});
ipcMain.handle('destructured', ({ senderFrame }, value) => {
  if (new URL(senderFrame.url).origin !== 'app://local') throw new Error('untrusted sender');
  return value;
});
ipcMain.on('by-url', (e, value) => {
  if (e.sender.getURL() !== 'app://local/index.html') return;
  console.log(value);
});
ipcMain.handle('helper', (event, value) => assertTrusted(event) && value);
ipcRenderer.on('from-main', (e) => console.log(e));
emitter.on('unrelated', () => {});
