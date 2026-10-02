// The dashboard is the only reader of terminal input. The CLI worker receives answers by prompt ID over IPC.
export const isTuiWorker = process.env.ELECTRONEGATIVITY_TUI_WORKER === '1' && typeof process.send === 'function';
export const interactiveTerminal = () => isTuiWorker || !!process.stdin.isTTY;

const pending = new Map();
let sequence = 0;
let liveSession = false;

export function tuiEvent(type, data = {}) {
  if (!isTuiWorker || !process.connected) return;
  if (type === 'session-live') liveSession = true;
  if (type === 'session-ended') liveSession = false;
  process.send({ type, ...data }, () => {});
}

export function tuiAsk(question, { kind = 'text', signal, ...details } = {}) {
  if (!process.connected || signal?.aborted) return Promise.resolve(undefined);
  const id = ++sequence;
  return new Promise(resolve => {
    const finish = answer => {
      if (!pending.delete(id)) return;
      signal?.removeEventListener('abort', abort);
      if (!pending.size) process.channel?.unref();
      resolve(answer);
    };
    const abort = () => { tuiEvent('cancel-prompt', { id }); finish(undefined); };
    pending.set(id, { finish, abort });
    process.channel?.ref();
    signal?.addEventListener('abort', abort, { once: true });
    tuiEvent('prompt', { id, kind, question, ...details });
  });
}

export function cancelTuiPrompts() {
  for (const item of [...pending.values()]) item.abort();
}

if (isTuiWorker) {
  process.on('message', message => {
    if (message?.type === 'answer' && pending.has(message.id)) pending.get(message.id).finish(message.answer);
    if (message?.type === 'stop-session' && liveSession && process.listenerCount('SIGINT')) {
      tuiEvent('phase', { text: 'Ending session; collecting evidence and writing reports…' });
      process.emit('SIGINT');
    }
  });
  process.once('disconnect', () => {
    cancelTuiPrompts();
    if (liveSession && process.listenerCount('SIGINT')) process.emit('SIGINT');
  });
  process.channel?.unref();
}

export function tuiConfirm() {
  const confirm = async question => (await tuiAsk(question, { kind: 'confirm' })) === 'y';
  confirm.ask = question => tuiAsk(question);
  confirm.offer = details => tuiAsk(`Campaign: ${details.key}`, { kind: 'campaign', ...details }).then(answer => answer === 'run');
  confirm.onCampaign = details => tuiEvent('campaign', details);
  confirm.cancel = cancelTuiPrompts;
  return confirm;
}
