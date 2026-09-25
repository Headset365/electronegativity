const { contextBridge, ipcRenderer, shell } = require('electron');

contextBridge.exposeInMainWorld('ipc', ipcRenderer);
contextBridge.exposeInMainWorld('api', {
  send: ipcRenderer.send,
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  onUpdate: (callback) => ipcRenderer.on('update', callback),
  open: (url) => shell.openExternal(url),
});
