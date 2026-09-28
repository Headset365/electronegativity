import path from 'node:path';
import { severity, confidence } from '../../attributes.js';

const base = (file) => path.basename(String(file || '')).toLowerCase();
const where = (issue) => `${path.basename(String(issue.file || ''))}:${issue.location ? issue.location.line : '?'}`;

/**
 * Which windows can reach each IPC channel: the main-process handler, the renderer files (preloads) that send on the
 * channel, and the windows loading those preloads. A preload that forwards any channel name (`invoke(channel, ...args)`)
 * gives its windows every channel. Channels the main process handles but no renderer code sends are listed apart: dead
 * or development-only handlers are still callable by any page with such a pass-through.
 */
export default class IpcChannelMapGlobalCheck {
  constructor() {
    this.id = 'IPC_CHANNEL_MAP_GLOBAL_CHECK';
    this.description = __('IPC_CHANNEL_MAP_GLOBAL_CHECK');
    this.depends = ['IpcRendererChannelJSCheck'];
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/tutorial/ipc';
  }

  async perform(rendererIssues, output, allIssues = []) {
    const handlers = new Map();
    for (const issue of allIssues) {
      const channel = issue.properties && issue.properties.channel;
      if (!channel || !['IPC_HANDLER_JS_CHECK', 'IPC_SENDER_VALIDATION_JS_CHECK'].includes(issue.id)) continue;
      if (!handlers.has(channel)) handlers.set(channel, issue);
    }
    if (handlers.size === 0) return [];
    const windows = allIssues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK' && i.properties && i.properties.preload);
    const sendersOf = new Map();
    const passThrough = new Set();
    for (const issue of rendererIssues) {
      const channel = issue.properties.channel;
      if (channel === '*') { passThrough.add(issue.file); continue; }
      if (!sendersOf.has(channel)) sendersOf.set(channel, new Set());
      sendersOf.get(channel).add(issue.file);
    }
    const windowsLoading = (files) => windows.filter(w => [...files].some(f => base(f) === base(w.properties.preload)));
    const results = [];
    for (const [channel, handler] of handlers) {
      const senders = new Set([...(sendersOf.get(channel) || []), ...passThrough]);
      const reach = windowsLoading(senders);
      const properties = { channel, handler: where(handler), senders: [...senders], windows: reach.map(where), passThrough: [...passThrough] };
      if (!sendersOf.has(channel)) {
        if (rendererIssues.length === 0) continue; // no renderer code in the scan: nothing to compare with
        results.push({ file: handler.file, location: handler.location, id: this.id, shortenedURL: this.shortenedURL, properties,
          severity: severity.LOW, confidence: confidence.TENTATIVE, manualReview: true,
          description: `${this.description}: '${channel}' is handled but no scanned renderer code sends it (dead or development-only${passThrough.size ? ', yet reachable through the pass-through in ' + [...passThrough].map(base).join(', ') : ''}; renderer code served remotely is not in the scan)` });
        continue;
      }
      results.push({ file: handler.file, location: handler.location, id: this.id, shortenedURL: this.shortenedURL, properties,
        severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false,
        description: `${this.description}: '${channel}' handled at ${where(handler)}, sent from ${[...senders].map(base).join(', ')}${reach.length ? `, reachable from ${reach.length} window(s): ${reach.map(where).join(', ')}` : ''}` });
    }
    return results;
  }
}
