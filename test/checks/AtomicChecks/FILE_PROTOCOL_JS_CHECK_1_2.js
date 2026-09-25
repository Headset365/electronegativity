win.loadFile(path.join(__dirname, 'index.html'));
win.loadURL(`file://${__dirname}/index.html`);
win.loadURL('app://bundle/index.html');
win.loadURL('https://example.com');
