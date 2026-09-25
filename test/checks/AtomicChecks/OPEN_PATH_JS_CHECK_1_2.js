const { shell } = require('electron');
shell.openPath(userSuppliedPath);
shell.openItem(file);
shell.openPath('/Applications');
