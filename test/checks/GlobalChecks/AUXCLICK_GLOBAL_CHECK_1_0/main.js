const win = new BrowserWindow();
win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
