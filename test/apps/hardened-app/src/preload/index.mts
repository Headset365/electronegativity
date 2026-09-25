import { contextBridge, ipcRenderer } from 'electron';

// #20: a narrow API, no ipcRenderer, no event objects
contextBridge.exposeInMainWorld('app', {
  getVersion: (): Promise<string> => ipcRenderer.invoke('get-version'),
  onUpdateAvailable: (callback: (version: string) => void) => ipcRenderer.on('update-available', (_event, version: string) => callback(version)),
});
