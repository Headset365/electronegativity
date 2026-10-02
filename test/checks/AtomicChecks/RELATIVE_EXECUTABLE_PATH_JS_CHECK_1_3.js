// programs resolved against the working directory
const { spawn, execFile } = require('child_process');
const path = require('path');
ADODB.PATH = './resources/adodb.js';
spawn('./bin/helper.exe', ['--sync']);
execFile('tools\\convert.exe', []);
// not reported: built from the app's own folders, a command on PATH, a data file
spawn(path.join(process.resourcesPath, 'helper.exe'));
execFile('reg', ['query', 'HKCU']);
config.path = './data/settings.json';
