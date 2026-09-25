win.webContents.on('new-window', (event) => event.preventDefault());
win.webContents.on('will-navigate', (event) => event.preventDefault());
