'use strict';
const fs = require('node:fs');
function loadProfile(file, ipc = false) {
  if (fs.statSync(file).size > 65536) throw new Error('Proof profile exceeds 64 KiB');
  return validateProfile(JSON.parse(fs.readFileSync(file, 'utf8')), ipc);
}
function validateProfile(p, ipc = false) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('Proof profile must be an object');
  if (ipc) {
    if (!Array.isArray(p.handlers) || !p.handlers.length || p.handlers.length > 8) throw new Error('IPC profile needs 1–8 reviewed read-only handlers');
    for (const h of p.handlers) {
      if (!h || !['read-only', 'file-read'].includes(h.contract) || h.reviewed !== true ||
          !/^[\w:.-]{1,100}$/.test(h.channel || '') || /(?:exec|spawn|command|terminal|delete|write|save|install|update)/i.test(h.channel) ||
          !Array.isArray(h.args) || JSON.stringify(h.args).length > 4096 || h.args.length > 8)
        throw new Error('Each IPC handler needs a reviewed read-only/file-read contract, bounded args and a non-command channel');
      if (h.contract === 'file-read' && !JSON.stringify(h.args).includes('$CANARY_PATH')) throw new Error('File-read IPC args must use $CANARY_PATH');
    }
    return { handlers: p.handlers };
  }
  const origins = p.origins || ['https://eng-proof.invalid'];
  if (!Array.isArray(origins) || !origins.length || origins.length > 8 || origins.some(o => {
    try { const u = new URL(o); return !['https:', 'http:'].includes(u.protocol) || u.origin !== o || !!u.username || !!u.password; } catch { return true; }
  })) throw new Error('Proof origins must be 1–8 exact HTTP(S) origins');
  const feeds = p.feeds || [];
  if (!Array.isArray(feeds) || feeds.length > 8 || feeds.some(url => {
    try { const u = new URL(url); return !['http:', 'https:'].includes(u.protocol) || !!u.username || !!u.password || !/(?:latest[^/]*\.ya?ml|RELEASES)$/i.test(u.pathname); } catch { return true; }
  })) throw new Error('Feeds must name up to eight exact latest.yml/RELEASES HTTP(S) URLs without credentials');
  const links = p.links || [];
  if (!Array.isArray(links) || links.length > 8 || links.some(l => !l || l.reviewed !== true ||
      !/^[a-z]:[\\/]/i.test(l.page || '') && !/^https?:\/\//i.test(l.page || '') ||
      !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,5}$/.test(l.method || '')))
    throw new Error('Links need a reviewed page URL prefix and a dotted page API method');
  const services = p.services || [];
  if (!Array.isArray(services) || services.length > 8 || services.some(s => !s || s.reviewed !== true ||
      !Number.isInteger(s.port) || s.port < 1 || s.port > 65535 || !['http', 'websocket'].includes(s.transport) ||
      !/^\/(?!\/)[^\r\n#]{0,200}$/.test(s.path || '') || ![true, false].includes(s.requiresAuth)))
    throw new Error('Services need a reviewed read-only route, loopback port, transport and requiresAuth policy');
  return { origins, feeds, links, services };
}
module.exports = { loadProfile, validateProfile };
