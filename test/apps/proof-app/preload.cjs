'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('fixture', { openLink: url => ipcRenderer.invoke('open-link', url) });
