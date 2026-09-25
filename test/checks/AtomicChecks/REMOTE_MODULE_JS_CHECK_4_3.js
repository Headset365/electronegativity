const remoteMain = require('@electron/remote/main');
remoteMain.initialize();
remoteMain.enable(win.webContents);
