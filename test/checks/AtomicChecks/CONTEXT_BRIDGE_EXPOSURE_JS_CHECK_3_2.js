const { contextBridge } = require('electron');
const { exec } = require('child_process');

const api = {
  require: require,
  run: (cmd) => exec(cmd),
  safe: () => exec('ls'),
};

contextBridge.exposeInIsolatedWorld(1004, 'api', api);
