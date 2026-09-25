const { protocol, ipcMain, net } = require('electron');

protocol.handle('app', (request) => net.fetch('file:///app/' + new URL(request.url).pathname));
ipcMain.handle('not-a-protocol', () => true);
