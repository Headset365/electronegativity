// the desktop build answers its clipper API without a token
const clipperMiddleware = isElectron ? [] : [auth.checkEtapiToken];
route(router, "/api/clipper/handshake", clipperMiddleware, clipper.handshake);
route(router, "/api/clipper/notes", clipperMiddleware, clipper.createNote);
app.use((req, res, next) => process.versions.electron ? next() : requireAuth(req, res, next));
// not reported: a choice between two checks, or an empty list against something that is not authentication
const checks = strict ? [auth.checkApiToken] : [auth.checkSession];
const plugins = isElectron ? [] : [compression()];
