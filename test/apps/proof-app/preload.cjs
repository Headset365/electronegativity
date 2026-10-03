'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('fixture', { openLink: url => ipcRenderer.invoke('open-link', url),
  save: input => ipcRenderer.invoke('electron-trpc', { method: 'request', operation: { path: 'files.saveFile', type: 'mutation', input } }) });
