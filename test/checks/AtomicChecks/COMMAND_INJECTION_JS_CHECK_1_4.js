const { exec, execSync, spawn } = require('child_process');
const cp = require('child_process');

ipcMain.handle('convert', (event, file) => {
  exec(`convert ${file} out.png`);
});
execSync('git rev-parse ' + branch);
spawn('sh', ['-c', userCommand], { shell: true });
cp.exec(command);

exec('ls -la');
spawn('git', ['status', branch]);
regex.exec(input);
