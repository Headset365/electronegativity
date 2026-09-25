win.webContents.openDevTools();
if (userSettings.showTools) {
  win.webContents.openDevTools({ mode: 'detach' });
}
if (process.env.NODE_ENV === 'development') {
  win.webContents.openDevTools({ mode: 'detach' });
}
if (!app.isPackaged) win.webContents.openDevTools();
isDev && win.webContents.toggleDevTools();
