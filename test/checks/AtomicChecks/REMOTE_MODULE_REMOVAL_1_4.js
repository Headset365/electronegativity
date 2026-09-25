const { remote } = require('electron');
const dialog = require('electron').remote.dialog;
const w = electron.remote.getCurrentWindow();
const win = new BrowserWindow({ webPreferences: { enableRemoteModule: true } });
const { app } = require('electron');
