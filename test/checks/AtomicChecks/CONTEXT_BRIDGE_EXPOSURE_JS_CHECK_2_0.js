const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  loadPreferences: () => ipcRenderer.invoke('load-prefs'),
  savePreference: (key, value) => ipcRenderer.send('save-pref', key, value),
  onUpdate: (callback) => ipcRenderer.on('update', (_event, value) => callback(value)),
  version: process.versions.electron,
});
