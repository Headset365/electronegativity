session.defaultSession.setPreloads([path.join(__dirname, 'preload.js')]);
const preloads = session.defaultSession.getPreloads();
session.defaultSession.registerPreloadScript({ type: 'frame', filePath: path.join(__dirname, 'preload.js') });
