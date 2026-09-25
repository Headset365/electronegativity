protocol.registerFileProtocol('app', (request, callback) => callback({ path: '/app' }));
protocol.interceptHttpProtocol('https', handler);
protocol.handle('app', () => new Response('ok'));
