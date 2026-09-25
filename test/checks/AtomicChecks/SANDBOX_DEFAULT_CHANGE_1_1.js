const a = new BrowserWindow({ webPreferences: { preload: 'preload.js' } });
const b = new BrowserWindow({ webPreferences: { sandbox: false } });
const c = new BrowserWindow({ webPreferences: { nodeIntegration: true } });
