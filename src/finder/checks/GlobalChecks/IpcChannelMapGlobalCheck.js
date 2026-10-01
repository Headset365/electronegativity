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
    const registrations = new Map();
    for (const issue of allIssues) {
      const channel = issue.properties && issue.properties.channel;
      if (!channel || !['IPC_HANDLER_JS_CHECK', 'IPC_SENDER_VALIDATION_JS_CHECK'].includes(issue.id)) continue;
      if (issue.id === 'IPC_HANDLER_JS_CHECK') {
        if (!registrations.has(channel)) registrations.set(channel, new Map());
        registrations.get(channel).set(`${issue.file}:${issue.location?.line}:${issue.location?.column}`, issue);
      }
      if (!handlers.has(channel) || issue.id === 'IPC_HANDLER_JS_CHECK') handlers.set(channel, issue);
    }
    if (handlers.size === 0) return [];
    const windows = allIssues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK' && i.properties && i.properties.preload);
    const apis = allIssues.filter(i => i.id === 'EXPOSED_API_JS_CHECK' && i.properties?.memberChannels);
    const sendersOf = new Map();
    const passThrough = new Set();
    for (const issue of rendererIssues) {
      if (issue.properties.direction === 'receive') continue;
      const channel = issue.properties.channel;
      if (channel === '*') { passThrough.add(issue.file); continue; }
      if (!sendersOf.has(channel)) sendersOf.set(channel, new Set());
      sendersOf.get(channel).add(issue.file);
    }
    for (const api of apis) for (const channels of Object.values(api.properties.memberChannels)) for (const channel of channels) {
      if (channel === '*') { passThrough.add(api.file); continue; }
      if (!sendersOf.has(channel)) sendersOf.set(channel, new Set());
      sendersOf.get(channel).add(api.file);
    }
    const matchWindow = (w, f) => {
      const preload = w.properties.preload;
      if (preload === 'dynamic path') return undefined;
      if (path.resolve(path.dirname(w.file), preload) === path.resolve(f)) return 'resolved-path';
      if (base(f) === base(preload)) return 'preload-basename-candidate';
    };
    const windowsLoading = files => windows.filter(w => [...files].some(f => matchWindow(w, f)));
    const results = [];
    for (const [channel, handler] of handlers) {
      const senders = new Set([...(sendersOf.get(channel) || []), ...passThrough]);
      const reach = windowsLoading(senders);
      const exposed = apis.flatMap(api => Object.entries(api.properties.memberChannels)
        .filter(([, channels]) => channels.includes(channel) || channels.includes('*'))
        .map(([member]) => ({ api: `window.${api.properties.world}.${member}`, file: api.file, line: api.location?.line })));
      const properties = { channel, handler: where(handler), senders: [...senders], windows: reach.map(where), passThrough: [...passThrough],
        exposedAPIs: exposed, windowMatch: 'resolved-path-or-explicit-candidate',
        windowAccess: reach.map(w => ({ file: w.file, line: w.location?.line, preload: w.properties.preload, partition: w.properties.partition,
          urls: w.properties.urls || [], match: [...senders].map(f => matchWindow(w, f)).filter(Boolean).sort()[0],
          frameAccess: 'subframe-and-navigation-access-unverified' })), context: handler.properties?.context,
        handlers: [...(registrations.get(channel)?.values() || [])].map(item => ({ file: item.file, line: item.location?.line, capabilities: item.properties?.capabilities,
          analysis: item.properties?.context?.status })),
        authorization: 'application-policy-and-server-controls-unverified' };
      if (!sendersOf.has(channel)) {
        if (rendererIssues.length === 0) continue; // no renderer code in the scan: nothing to compare with
        results.push({ file: handler.file, location: handler.location, id: this.id, shortenedURL: this.shortenedURL, properties,
          severity: severity.LOW, confidence: confidence.TENTATIVE, manualReview: true,
          description: `${this.description}: '${channel}' is handled but no scanned renderer code sends it (dead or development-only${passThrough.size ? ', yet reachable through the pass-through in ' + [...passThrough].map(base).join(', ') : ''}; renderer code served remotely is not in the scan)` });
        continue;
      }
      results.push({ file: handler.file, location: handler.location, id: this.id, shortenedURL: this.shortenedURL, properties,
        severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false,
        description: `${this.description}: '${channel}' handled at ${where(handler)}, sent from ${[...senders].map(base).join(', ')}${reach.length ? `, ${reach.length} candidate window(s) matched by preload filename: ${reach.map(where).join(', ')}` : ''}${exposed.length ? `; exposed as ${exposed.map(e => e.api).join(', ')}` : ''}` });
    }
    return results;
  }
}
