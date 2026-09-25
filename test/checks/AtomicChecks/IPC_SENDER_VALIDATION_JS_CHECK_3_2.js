const { ipcMain, shell } = require('electron');
const { externalHandler } = require('./handlers');

function openFile(event, p) {
  return shell.openPath(p);
}

ipcMain.handle('open', openFile);
ipcMain.handle('external', externalHandler);
