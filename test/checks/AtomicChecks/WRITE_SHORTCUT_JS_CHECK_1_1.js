const { shell } = require('electron');
shell.writeShortcutLink(shortcutPath, 'create', { target: targetFromRenderer });
