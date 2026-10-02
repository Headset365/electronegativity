import fs from 'node:fs';
export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function until(fn, label, timeout = 90000, cancelled = () => false) {
  const end = Date.now() + timeout; let last;
  while (Date.now() < end) { if (cancelled()) throw Error(label + ' cancelled because its process exited'); try { const value = await fn(); if (value) return value; } catch (e) { last = e; } await delay(500); }
  throw Error(label + ' timed out' + (last ? ': ' + last.message : ''));
}
export async function connect(port, match = () => true, timeout, cancelled) {
  const target = await until(async () => {
    const r = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(2000) });
    return (await r.json()).find(t => t.type === 'page' && t.webSocketDebuggerUrl && match(t));
  }, 'Renderer debugger target', timeout, cancelled);
  const ws = new WebSocket(target.webSocketDebuggerUrl); const pending = new Map(); let serial = 0;
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  ws.onmessage = event => { const msg = JSON.parse(event.data); const p = pending.get(msg.id); if (p) { pending.delete(msg.id); clearTimeout(p.timer); msg.error ? p.reject(Error(JSON.stringify(msg.error))) : p.resolve(msg.result); } };
  ws.onclose = () => { for (const p of pending.values()) { clearTimeout(p.timer); p.reject(Error('Renderer disconnected')); } pending.clear(); };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++serial; const timer = setTimeout(() => { pending.delete(id); reject(Error('CDP timeout: ' + method)); }, 30000);
    pending.set(id, { resolve, reject, timer }); ws.send(JSON.stringify({ id, method, params }));
  });
  await send('Runtime.enable'); await send('Page.enable');
  return { target, send, close: () => ws.close(),
    async eval(expression) { const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text); return r.result?.value; },
    async screenshot(file) { const r = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(file, Buffer.from(r.data, 'base64')); },
    async state() { return await this.eval(`({url:location.href,title:document.title,text:document.body?.innerText.slice(0,16000),inputs:[...document.querySelectorAll('input,textarea,[contenteditable=true]')].slice(0,30).map(e=>({tag:e.tagName,placeholder:e.getAttribute('placeholder'),name:e.getAttribute('name'),type:e.getAttribute('type'),html:e.outerHTML.slice(0,500)})),buttons:[...document.querySelectorAll('button,[role=button]')].slice(0,65).map(e=>({text:e.innerText,label:e.getAttribute('aria-label'),title:e.getAttribute('title')}))})`); }
  };
}
