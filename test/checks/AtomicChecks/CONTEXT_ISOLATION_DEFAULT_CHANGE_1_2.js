const a = new BrowserWindow();
const b = new BrowserWindow({ webPreferences: { preload: 'preload.js' } });
const c = new BrowserWindow({ webPreferences: { contextIsolation: true } });
