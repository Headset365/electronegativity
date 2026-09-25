const { protocol } = require('electron');

protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { standard: true, secure: true, bypassCSP: true, corsEnabled: true } }
]);
