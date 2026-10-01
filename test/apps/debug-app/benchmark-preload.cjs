const {contextBridge,ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('probe',{read:p=>ipcRenderer.invoke('probe-read',p)});
