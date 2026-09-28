import path from 'node:path';
import { severity, confidence } from '../../attributes.js';

const where = (issue) => `${path.basename(String(issue.file || ''))}:${issue.location ? issue.location.line : '?'}`;
const on = (setting) => setting && setting.value === true;
const off = (setting) => setting && setting.value === false;

// A window page script could get far from: Node.js in the page, the preload's world shared with the page, no sandbox, or a preload
function privileged(window) {
  const s = window.properties.settings || {};
  return on(s.nodeIntegration) || off(s.contextIsolation) || off(s.sandbox) || !!window.properties.preload;
}

/**
 * Windows sharing a session share cookies, Local Storage, IndexedDB, service workers and permission grants. That is
 * expected between the app's own windows; a window without privileges (e.g. one showing documents or third-party pages)
 * in the same session as a privileged one is worth a look: what it can read and do is the privileged window's session.
 */
export class WindowSessionGlobalCheck {
  constructor() {
    this.id = 'WINDOW_SESSION_GLOBAL_CHECK';
    this.description = __('WINDOW_SESSION_GLOBAL_CHECK');
    this.depends = [];
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/session';
  }

  async perform(issues, output, allIssues = []) {
    const windows = allIssues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK' && i.properties && i.properties.partition && i.properties.partition !== 'unknown');
    if (windows.length < 2) return [];
    const groups = new Map();
    for (const window of windows) {
      const key = window.properties.partition;
      if (key === 'dynamic' || key === 'custom session') continue; // can't tell which session
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(window);
    }
    const results = [];
    for (const [partition, members] of groups) {
      if (members.length < 2) continue;
      const strong = members.filter(privileged);
      const weak = members.filter(w => !privileged(w));
      const name = partition === 'default' ? 'the default session' : `session '${partition}'`;
      const properties = { partition, windows: members.map(where), privileged: strong.map(where), unprivileged: weak.map(where) };
      if (strong.length && weak.length)
        results.push({ file: weak[0].file, location: weak[0].location, id: this.id, shortenedURL: this.shortenedURL, properties,
          severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description}: ${weak.map(where).join(', ')} (no preload or Node.js) share ${name} with ${strong.map(where).join(', ')}: cookies, storage and permission grants are common; give windows that show untrusted content their own partition` });
      else
        results.push({ file: members[0].file, location: members[0].location, id: this.id, shortenedURL: this.shortenedURL, properties,
          severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false,
          description: `${this.description}: ${members.length} windows share ${name} (${members.map(where).join(', ')})` });
    }
    return results;
  }
}

/**
 * will-navigate is not emitted for server-side redirects: a window whose navigation allowlist lives only in
 * will-navigate follows a redirect from an allowed page (an open redirect, a compromised link shortener) to any origin,
 * with its preload. will-redirect, did-start-navigation or a webRequest filter covers it.
 */
export class NavigationRedirectGlobalCheck {
  constructor() {
    this.id = 'NAVIGATION_REDIRECT_GLOBAL_CHECK';
    this.description = __('NAVIGATION_REDIRECT_GLOBAL_CHECK');
    this.depends = ['NavigationRedirectJSCheck'];
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/web-contents#event-will-redirect';
  }

  async perform(redirectHandlers, output, allIssues = []) {
    const allowlists = allIssues.filter(i => i.id === 'LIMIT_NAVIGATION_JS_CHECK' && i.properties &&
      ['will-navigate', 'will-frame-navigate'].includes(i.properties.event) && i.severity.value > severity.INFORMATIONAL.value);
    if (allowlists.length === 0) return [];
    if (redirectHandlers.some(h => h.properties.blocks)) return [];
    const first = allowlists[0];
    const partial = redirectHandlers.length > 0;
    return [{ file: first.file, location: first.location, id: this.id, shortenedURL: this.shortenedURL,
      severity: severity.MEDIUM, confidence: partial ? confidence.TENTATIVE : confidence.FIRM, manualReview: true,
      properties: { allowlists: allowlists.map(where), redirectHandlers: redirectHandlers.map(where) },
      description: `${this.description} (${allowlists.map(where).join(', ')}${partial ? `; the redirect handlers at ${redirectHandlers.map(where).join(', ')} never block` : ''})` }];
  }
}

// The directive that governs a resource type, following CSP's fallback chain
const FALLBACK = {
  'frame-src': ['frame-src', 'child-src', 'default-src'],
  'connect-src': ['connect-src', 'default-src'],
  'img-src': ['img-src', 'default-src'],
  'style-src': ['style-src', 'default-src'],
  'font-src': ['font-src', 'default-src'],
  'media-src': ['media-src', 'default-src'],
};
const ANYWHERE = /^(\*|https?:|https?:\/\/\*|wss?:)$/i;

export function parsePolicy(policy) {
  const directives = new Map();
  for (const part of String(policy || '').split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), sources);
  }
  return directives;
}

/** What a policy lets page content load or send, beyond scripts and objects (which csp-evaluator covers). */
export function directiveProblems(policy) {
  const directives = parsePolicy(policy);
  const effective = (type) => { const name = FALLBACK[type].find(d => directives.has(d)); return name ? directives.get(name) : undefined; };
  const problems = [];
  const open = (type) => { const sources = effective(type); return !sources ? 'not restricted' : sources.find(s => ANYWHERE.test(s)) ? `allows ${sources.find(s => ANYWHERE.test(s))}` : undefined; };
  const frame = open('frame-src');
  if (frame) problems.push({ directive: 'frame-src', text: `frame-src ${frame}: content can embed any site`, weight: 2 });
  const frameSources = effective('frame-src') || [];
  if (frameSources.some(s => /^(data:|blob:)$/i.test(s))) problems.push({ directive: 'frame-src', text: 'frame-src allows data: or blob: documents', weight: 2 });
  const connect = open('connect-src');
  if (connect) problems.push({ directive: 'connect-src', text: `connect-src ${connect}: injected script can send data to any server`, weight: 2 });
  const img = open('img-src');
  if (img) problems.push({ directive: 'img-src', text: `img-src ${img}: content can load images from anywhere (tracking, leaking data in image URLs)`, weight: 1 });
  const style = effective('style-src');
  if (!style) problems.push({ directive: 'style-src', text: 'style-src not restricted: CSS from anywhere', weight: 1 });
  else if (style.find(s => ANYWHERE.test(s))) problems.push({ directive: 'style-src', text: `style-src allows ${style.find(s => ANYWHERE.test(s))}`, weight: 1 });
  else if (style.includes("'unsafe-inline'")) problems.push({ directive: 'style-src', text: "style-src allows 'unsafe-inline': injected markup can carry CSS (data leaks through selectors, UI redressing)", weight: 1 });
  if (!directives.has('form-action')) problems.push({ directive: 'form-action', text: 'form-action not set: injected forms can post anywhere', weight: 1 });
  return problems;
}

/** The directives csp-evaluator does not rate: frames, connections, images, styles and forms. */
export class CSPDirectivesGlobalCheck {
  constructor() {
    this.id = 'CSP_DIRECTIVES_GLOBAL_CHECK';
    this.description = __('CSP_DIRECTIVES_GLOBAL_CHECK');
    this.depends = ['CSPJSCheck', 'CSPHTMLCheck'];
    this.shortenedURL = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy';
  }

  async perform(policies) {
    const results = [];
    const seen = new Set();
    for (const issue of policies) {
      const policy = issue.properties && issue.properties.CSPstring;
      if (!policy || !Array.isArray(issue.visibility && issue.visibility.excludesGlobal) || issue.visibility.excludesGlobal.includes(this.id)) continue;
      const problems = directiveProblems(policy);
      if (problems.length === 0) continue;
      const key = `${issue.file}\n${policy}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const serious = problems.some(p => p.weight > 1);
      results.push({ file: issue.file, location: issue.location, id: this.id, shortenedURL: this.shortenedURL, sample: policy,
        severity: serious ? severity.LOW : severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: serious,
        properties: { directives: problems.map(p => p.directive) },
        description: `${this.description}: ${problems.map(p => p.text).join('; ')}` });
    }
    // one policy for every page: the document viewer, if there is one, gets the same rules as the app's own UI
    const distinct = new Set(policies.map(i => i.properties && i.properties.CSPstring).filter(Boolean));
    const files = new Set(policies.map(i => i.file));
    if (distinct.size === 1 && files.size > 1)
      results.push({ file: policies[0].file, location: policies[0].location, id: this.id, shortenedURL: this.shortenedURL,
        severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: true, properties: { sharedPolicy: true },
        description: `${this.description}: the same policy applies to all ${files.size} pages; pages that show untrusted documents usually need a stricter one than the app's own UI` });
    return results;
  }
}
