const { shell } = require('electron');
shell.showItemInFolder(downloadPath);
shell.showItemInFolder('/tmp/report.pdf');
