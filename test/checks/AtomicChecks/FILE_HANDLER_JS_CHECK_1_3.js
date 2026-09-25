const { app } = require('electron');
app.on('open-file', (event, path) => openDocument(path));
app.on('open-url', (event, url) => handleDeepLink(url));
app.on('second-instance', (event, argv) => handleArgs(argv));
app.on('ready', createWindow);
