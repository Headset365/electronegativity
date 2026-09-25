win.webContents.setWindowOpenHandler(({ url }) => {
  if (url.startsWith('https://example.com/')) {
    return { action: 'allow' };
  }
  return { action: 'deny' };
});

win.webContents.setWindowOpenHandler(() => ({
  action: 'allow',
  overrideBrowserWindowOptions: { webPreferences: { nodeIntegration: true } }
}));
