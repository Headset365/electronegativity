// Passive evidence only: never probes a path or substitutes the module the app requested.
const { redactText } = require('../traffic/secrets.cjs');
function observeModuleLoads(load, { marker, resolve, record }) {
  const active = typeof marker === 'string' && /^[A-Za-z0-9_-]{8,80}$/.test(marker);
  return function (request, parent, ...args) {
    if (!active || typeof request !== 'string' || !request.includes(marker)) return load.call(this, request, parent, ...args);
    let resolved, ok = false, errorCode;
    try { resolved = resolve(request, parent, ...args); } catch { /* resolution evidence is optional */ }
    try {
      const result = load.call(this, request, parent, ...args);
      ok = true;
      return result;
    } catch (error) {
      errorCode = error && error.code;
      throw error;
    } finally {
      try { record({ kind: 'module-load', marker: true, request: redactText(request).slice(0, 300), resolved: typeof resolved === 'string' ? redactText(resolved).slice(0, 500) : undefined,
        parent: typeof parent?.filename === 'string' ? redactText(parent.filename).slice(0, 500) : undefined, ok, errorCode }); } catch { /* never change app behavior */ }
    }
  };
}

module.exports = { observeModuleLoads };
