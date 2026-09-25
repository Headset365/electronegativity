const { protocol, net, app } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

// vulnerable: /../../etc/passwd escapes the app directory
protocol.handle('app', (request) => {
  const { pathname } = new URL(request.url);
  return net.fetch(pathToFileURL(path.join(__dirname, pathname)).toString());
});

// safe: the resolved path must stay inside the app directory
protocol.handle('safe', (request) => {
  const filePath = path.resolve(__dirname, new URL(request.url).pathname.slice(1));
  if (!filePath.startsWith(__dirname + path.sep)) return new Response('forbidden', { status: 403 });
  return net.fetch(pathToFileURL(filePath).toString());
});

// no files involved
protocol.handle('status', () => new Response('ok'));
