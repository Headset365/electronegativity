contextBridge.exposeInMainWorld('ipc', ipcRenderer);
contextBridge.exposeInMainWorld('api', { ipc: ipcRenderer, version: '1' });
contextBridge.exposeInMainWorld('safe', { ping: () => ipcRenderer.invoke('ping') });
