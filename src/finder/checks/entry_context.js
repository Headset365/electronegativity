import { ipcContext, ipcDefinition } from './ipc_context.js';

/** Reuse bounded per-argument traversal without treating the first input as an IPC sender. */
export function entryContext(node, scope, ancestors, sources) {
  const definition = ipcDefinition(node, scope, ancestors);
  return ipcContext(definition, { sources });
}

export function flowDescription(context) {
  const effects = context.effects.filter(effect => effect.arguments.length);
  const capabilities = [...new Set(effects.map(effect => effect.capability))];
  return `${capabilities.length ? `input reaches ${capabilities.join(', ')}` : 'no input-dependent operation resolved'}; ${context.status === 'incomplete' ? 'analysis incomplete' : 'bounded analysis complete'}. Recognized guards require validation.`;
}
