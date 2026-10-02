'use strict';
// A tool-created foreign renderer gets only this bridge. It is not evidence that
// the application exposes an IPC bridge to untrusted content by itself.
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('engProof', { invoke: (channel, args) => ipcRenderer.invoke(channel, ...args) });
