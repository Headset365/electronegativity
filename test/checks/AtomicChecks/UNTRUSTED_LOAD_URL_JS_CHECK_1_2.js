ipcMain.on('open-page', (event, url) => {
  win.loadURL(url);
});
app.on('open-url', (event, link) => {
  const target = link.replace('myapp://', 'https://');
  win.loadURL(target);
});
ipcMain.on('open-docs', (event, page) => {
  win.loadURL(`https://docs.example.com/${page}`);
});
win.loadURL(config.startUrl);
