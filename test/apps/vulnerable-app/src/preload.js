const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('ipc', ipcRenderer);
window.render = (html) => { document.body.innerHTML = html; };
