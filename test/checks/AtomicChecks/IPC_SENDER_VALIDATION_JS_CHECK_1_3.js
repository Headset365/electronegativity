const { ipcMain } = require('electron');
const fs = require('fs');

ipcMain.handle('read-file', async (event, path) => fs.promises.readFile(path));
ipcMain.on('log', (_event, msg) => console.log(msg));
ipcMain.handle('reply', (event) => {
  event.sender.send('pong');
});
