const { autoUpdater } = require("electron-updater");
autoUpdater.setFeedURL({ provider: "generic", url: `https://example.com/api/v1/releases/${process.platform}/${track}` });
