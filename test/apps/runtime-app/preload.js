const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('app', {
  getDocument: (id) => ipcRenderer.invoke('documents:get', id),
  log: (message) => ipcRenderer.send('log', message),
});
