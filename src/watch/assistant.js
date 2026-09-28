// The validation assistant: while a watch session runs, it reads what the hook records and tells the tester what to do
// next to confirm or rule out the findings that need review ("send that request again with the marker in its fields",
// "click the link", "you pasted plain text, now paste formatted text"), and what the marker has shown so far.
//
// Everything here uses the harmless marker only: a token, the token in a <span data-...> element, a link to
// https://example.invalid/<token> and a text file named after it. Where the marker ends up shows whether content from
// another user can reach an HTML sink, openExternal, a navigation, IPC or a command line; nothing is attacked.
import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';
import { apiRoute } from './analyze.js';

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const WEB_SCHEMES = new Set(['http', 'https', 'mailto']);
const HTML_REVIEW = new Set(['XSS_SINK_JS_CHECK', 'ANGULAR_TRUST_HTML_JS_CHECK', 'RICH_TEXT_EDITOR_JS_CHECK', 'SANITIZER_CONFIG_JS_CHECK', 'ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK', 'DANGEROUS_FUNCTIONS_JS_CHECK']);
const LINK_REVIEW = new Set(['OPEN_EXTERNAL_JS_CHECK', 'LIMIT_NAVIGATION_JS_CHECK', 'LIMIT_NAVIGATION_GLOBAL_CHECK', 'WINDOW_OPEN_HANDLER_JS_CHECK', 'UNTRUSTED_LOAD_URL_JS_CHECK', 'AUXCLICK_JS_CHECK']);

export const markerForms = (marker) => ({
  text: marker,
  html: `<span data-${marker}="1">${marker}</span>`,
  link: `https://example.invalid/${marker}`,
  fileLink: (platform) => platform === 'win32' ? `file:///C:/Windows/#${marker}` : platform === 'darwin' ? `file:///Applications/#${marker}` : `file:///tmp/#${marker}`,
  file: `${marker}.txt`,
});

/**
 * Writes the files the tester uses: a page to open in a browser and copy (so the marker is pasted as formatted HTML,
 * with a link), and a text file named after the marker (to attach or open). Returns their paths.
 */
export function writeMarkerFiles(dir, marker) {
  const forms = markerForms(marker);
  const page = path.join(dir, `${marker}-paste-me.html`);
  fs.writeFileSync(page, `<!doctype html><meta charset="utf-8"><title>${marker}</title>
<p>Select everything below, copy it, and paste it into the app's editor or a comment field.</p><hr>
<p>Validation test <b>${marker}</b> ${forms.html} <a href="${forms.link}">link ${marker}</a></p>
`);
  const file = path.join(dir, forms.file);
  fs.writeFileSync(file, `${marker}\n`);
  return { page, file };
}

const frameText = (frame) => frame ? `${frame.url}:${frame.line}:${frame.column}` : 'an unknown script';
const originOf = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return String(url || '');
  }
};

/**
 * @param {{ marker?: string, staticIssues?: Array, files?: { page, file }, print?: Function }} options
 */
export function createAssistant({ marker, staticIssues = [], files, print = (line) => console.log(line) } = {}) {
  const forms = marker ? markerForms(marker) : undefined;
  const say = {
    next: (text) => print(chalk.cyan(`[validate] → ${text}`)),
    good: (text) => print(chalk.green(`[validate] ✓ ${text}`)),
    bad: (text) => print(chalk.red(`[validate] ✗ ${text}`)),
    note: (text) => print(chalk.yellow(`[validate] ! ${text}`)),
  };
  const once = new Set();
  const first = (key) => !once.has(key) && once.add(key);
  const state = {
    platform: process.platform, pageOrigins: new Map(), asked: new Map(), sent: new Map(), rendered: [], sinks: [], links: [],
    paths: [], commands: [], ipc: new Map(), entries: new Set(),
    // set for the current session when the tool can re-send the marker request itself: { confirm(question)->bool, send(command) }
    channel: undefined, confirming: false, autoSent: new Set(),
  };
  const review = staticIssues.filter(i => i.manualReview || HTML_REVIEW.has(i.id) || LINK_REVIEW.has(i.id) || i.id === 'OPEN_PATH_JS_CHECK');
  const count = (ids) => review.filter(i => ids.has(i.id)).length;
  const place = (issue) => `${issue.file}${issue.location && issue.location.line ? ':' + issue.location.line : ''}`;

  function intro() {
    if (!marker) {
      say.note('No marker for this session: run with --watch-marker <token> (or use --app, which makes one) to check the findings that need review automatically.');
      return;
    }
    print(chalk.cyan.bold(`[validate] Validation assistant. Marker for this session: ${marker}`));
    print(chalk.cyan(`[validate]   text fields (titles, names, comments): ${forms.text}`));
    print(chalk.cyan(`[validate]   rich-text / HTML fields:                ${forms.html}`));
    print(chalk.cyan(`[validate]   links:                                  ${forms.link}`));
    if (files) {
      print(chalk.cyan(`[validate]   formatted copy to paste: open ${files.page} in a browser, select all, copy, paste into the editor`));
      print(chalk.cyan(`[validate]   file to attach or open:  ${files.file}`));
    }
    const html = count(HTML_REVIEW);
    const links = count(LINK_REVIEW);
    const paths = count(new Set(['OPEN_PATH_JS_CHECK']));
    const ipc = count(new Set(['IPC_SENDER_VALIDATION_JS_CHECK']));
    if (html) say.next(`The static scan found ${html} place(s) that write data as HTML. Save content carrying the HTML marker (paste the formatted copy, or put the HTML marker in the editor's source/HTML view), then view it: here, or signed in as the second account. Each place the markup reaches is confirmed automatically.`);
    if (links) say.next(`${links} finding(s) are about links and navigation. Add the link ${forms.link} to shared content (a document, a comment) and click it; also try Ctrl+click and middle-click.`);
    if (paths) say.next(`${paths} finding(s) open files with their default program. If the app handles attachments or file names from content, attach ${files ? files.file : forms.file} and open it from the app.`);
    if (ipc) say.note(`${ipc} IPC handler(s) don't check which page sent the message. That can't be tested by using the app: read each handler for an event.senderFrame check. The report lists which origins used each channel.`);
    if (!html && !links && !paths) say.next('Put the marker in every field you can save (text marker in plain fields, HTML marker in rich text), add the link to shared content, then view it all as the second account.');
    print(chalk.cyan('[validate] I\'ll say what the marker shows as it travels, and what to try next.'));
  }

  function staticAt(frame) {
    if (!frame) return undefined;
    return review.find(i => HTML_REVIEW.has(i.id) && i.location && i.location.line === frame.line &&
      (String(i.file) === frame.url || String(frame.url).endsWith(`/${path.basename(String(i.file))}`)));
  }

  function handle(r) {
    if (!r || typeof r !== 'object') return;
    if (r.kind === 'start' && r.platform) state.platform = r.platform;
    if (!marker) return;
    switch (r.kind) {
      case 'api': {
        if (!WRITE_METHODS.has(String(r.method).toUpperCase()) || !Array.isArray(r.fields) || r.fields.length === 0 || (r.status && r.status >= 400)) break;
        const route = apiRoute(r.url) || r.url;
        const key = `${r.method} ${route}`;
        const withMarker = r.fields.filter(f => f.marker);
        if (withMarker.length > 0) {
          state.sent.set(key, [...new Set([...(state.sent.get(key) || []), ...withMarker.map(f => f.name)])]);
          // when we sent it ourselves the marker-request result already reported it: don't say it twice
          if (first(`sent:${key}:${withMarker.map(f => f.name).join(',')}`) && !state.autoSent.has(key)) {
            const asHtml = withMarker.filter(f => f.html).map(f => f.name);
            say.good(`The marker was sent with ${key} in: ${withMarker.map(f => f.name).join(', ')}${asHtml.length ? ` (as HTML in: ${asHtml.join(', ')})` : ''}. Now view that content: reload it here, or open it signed in as the second account.`);
          }
        } else if (!state.sent.has(key) && first(`ask:${key}`)) {
          const html = r.fields.filter(f => f.html).map(f => f.name);
          const text = r.fields.filter(f => !f.html).map(f => f.name);
          state.asked.set(key, { html, text });
          const list = (names) => names.slice(0, 8).join(', ') + (names.length > 8 ? `, and ${names.length - 8} more` : '');
          const manual = () => say.next(`Saw ${key}${html.length ? ` carrying HTML in: ${list(html)}` : ''}${text.length ? `${html.length ? '; text in' : ' with fields'}: ${list(text)}` : ''}. Send it again with the marker: ${forms.text} in the text fields${html.length ? ` and ${forms.html} in ${list(html)}` : ''}. Use the app (the editor's HTML/source view if it has one), or replay this request from your proxy.`);
          const channel = state.channel;
          // if the tool can re-send the request itself, show exactly what it would send and ask before doing it
          if (channel && channel.confirm && channel.send && r.replay !== undefined && !state.confirming) {
            const fill = r.fields.map(f => ({ name: f.name, html: !!f.html }));
            const shown = fill.map(f => `${f.name}=${f.html ? forms.html : forms.text}`);
            say.next(`Saw ${key}${html.length ? ` carrying HTML in: ${list(html)}` : ''}${text.length ? `${html.length ? '; text in' : ' with fields'}: ${list(text)}` : ''}. I can re-send it for you, through the app's own session, with the marker in: ${list(fill.map(f => f.name))} — ${shown.slice(0, 8).join('; ')}${shown.length > 8 ? '; …' : ''}.`);
            state.confirming = true;
            Promise.resolve(channel.confirm(`[validate] Send ${key} with the marker now? [Y/n] `))
              .then(yes => {
                if (yes) {
                  channel.send({ kind: 'send-marker', replay: r.replay, method: r.method, route, fields: fill });
                  say.next(`Sending ${key} with the marker…`);
                } else {
                  say.note('Not sending it. To check this endpoint yourself:');
                  manual();
                }
              })
              .catch(() => manual())
              .finally(() => { state.confirming = false; });
          } else {
            manual();
          }
        }
        break;
      }
      case 'marker-request': {
        // the result of a request the tool re-sent itself, after the tester confirmed it
        const key = r.route ? `${r.method} ${r.route}` : (r.method ? `${r.method} request` : 'the request');
        if (r.ok) {
          state.autoSent.add(key);
          state.sent.set(key, [...new Set([...(state.sent.get(key) || []), ...(r.fields || [])])]);
          if (first(`marker-request:${key}`)) {
            const asHtml = r.html || [];
            say.good(`Sent ${key} with the marker${r.fields && r.fields.length ? ` in: ${r.fields.join(', ')}` : ''}${asHtml.length ? ` (as HTML in: ${asHtml.join(', ')})` : ''}${r.status ? ` (status ${r.status})` : ''}. Now view that content: reload it here, or open it signed in as the second account.`);
          }
        } else if (first(`marker-request-failed:${key}`)) {
          say.note(`I couldn't send ${key} automatically${r.status ? ` (status ${r.status})` : r.error ? ` (${r.error})` : ''}. Send it through the app, or replay it from your proxy, with the marker in its fields.`);
        }
        break;
      }
      case 'dom-observed':
        if (r.event !== 'marker') break;
        {
          const where = `${r.url}${r.frame ? ` (in the frame ${r.frame}, e.g. an editor)` : ''}`;
          if (r.live && first(`live:${originOf(r.url)}:${!!r.frame}`)) {
            state.rendered.push({ url: where, live: true });
            say.bad(`The marker came back as live HTML at ${where}: stored content is rendered as markup there.`);
          } else if (!r.live && first(`text:${originOf(r.url)}:${!!r.frame}`)) {
            state.rendered.push({ url: where, live: false });
            say.good(`The marker was shown as text at ${where}.`);
          }
        }
        break;
      case 'sink': {
        if (!r.live) break;
        const frame = (r.frames || [])[0];
        if (!first(`sink:${r.sink}:${frameText(frame)}`)) break;
        state.sinks.push({ sink: r.sink, frame, url: r.url });
        const finding = staticAt(frame);
        say.bad(`Markup carrying the marker was written with ${r.sink} by ${frameText(frame)}${finding ? `: confirms ${finding.id} at ${place(finding)}` : ''}.`);
        break;
      }
      case 'shell':
        if (!r.marker) break;
        if (r.method === 'openExternal') {
          const web = WEB_SCHEMES.has(String(r.scheme || '').toLowerCase());
          state.links.push({ kind: 'openExternal', scheme: r.scheme, web });
          if (web && first('external-web')) say.note(`A link from content was handed to the operating system (shell.openExternal). Now try the same link as ${forms.fileLink(state.platform)}: if a folder opens, the app passes links of any scheme to the OS.`);
          if (!web && first(`external:${r.scheme}`)) say.bad(`A ${r.scheme}: link from content was passed to the operating system by shell.openExternal: the app has no scheme allowlist.`);
        } else if (first(`path:${r.method}`)) {
          state.paths.push({ method: r.method });
          say.bad(`A path containing the marker was opened by shell.${r.method}: content chooses which file the app opens. Check which file types it will open.`);
        }
        break;
      case 'will-navigate':
        if (!r.marker) break;
        state.links.push({ kind: 'navigate', prevented: !!r.prevented, url: r.url });
        if (r.prevented) {
          if (first('nav-blocked')) say.good('The app blocked the window from navigating to the marker link.');
        } else if (first(`nav:${originOf(r.url)}`)) say.bad(`A link from content navigated the app window to ${originOf(r.url)}: that page runs with the window's preload and IPC access.`);
        break;
      case 'window-open':
        if (!r.marker) break;
        state.links.push({ kind: 'window', action: r.action, default: !!r.default });
        if (r.action === 'deny') {
          if (first('window-denied')) say.good('The app refused to open a window for the marker link.');
        } else if (first('window-allowed')) say.bad(`A link from content opened a new app window${r.default ? ' (the app has no setWindowOpenHandler)' : ''}.`);
        break;
      case 'did-navigate': {
        const target = originOf(r.url);
        if (!/^https?:/i.test(r.url || '')) break;
        if (!state.pageOrigins.has(r.id)) state.pageOrigins.set(r.id, target);
        else if (state.pageOrigins.get(r.id) !== target && !r.marker && first(`went:${target}`))
          say.note(`A window went to ${target}. If that isn't your app or its sign-in provider, find out what sent it there: that page gets the window's preload and IPC access.`);
        break;
      }
      case 'ipc':
        if (!r.marker || !first(`ipc:${r.channel}`)) break;
        state.ipc.set(r.channel, r.sender);
        say.note(`Content carrying the marker reached IPC channel '${r.channel}'${r.sender ? ` from ${originOf(r.sender)}` : ''}: check that its handler validates the sender and the value.`);
        break;
      case 'process':
        if (!r.marker || !first(`process:${r.program}`)) break;
        state.commands.push({ program: r.program, method: r.method });
        say.bad(`The marker reached a command the app runs (${r.program}, via ${r.method}): content controls part of a command line.`);
        break;
      case 'entry':
        state.entries.add(r.detail);
        if (r.detail === 'paste-text' && !state.entries.has('paste-html') && first('paste-html-hint'))
          say.next(`You pasted plain text. Also paste formatted content${files ? `: open ${files.page} in a browser, select all, copy, and paste it here` : ' (copied from a web page or Word) containing the marker'}.`);
        break;
      default:
    }
  }

  /** What has been validated, ruled out or is still to do, for the end-of-session summary. */
  function summary() {
    if (!marker) return [];
    const items = [];
    const live = state.rendered.filter(r => r.live);
    if (live.length) items.push({ status: 'confirmed', text: `stored content rendered as live HTML at ${live.map(r => r.url).join(', ')}` });
    else if (state.rendered.length) items.push({ status: 'safe', text: `the marker was shown as text wherever it appeared (${state.rendered.length} page${state.rendered.length === 1 ? '' : 's'})` });
    else items.push({ status: 'todo', text: 'the marker was never seen in a page: save content with it and view it (here or as the second account)' });
    for (const s of state.sinks) items.push({ status: 'confirmed', text: `markup reached ${s.sink} at ${frameText(s.frame)}` });
    for (const [key, fields] of state.sent) items.push({ status: 'done', text: `marker sent with ${key} (${fields.join(', ')})` });
    for (const [key] of state.asked) if (!state.sent.has(key)) items.push({ status: 'todo', text: `send ${key} again with the marker in its fields` });
    const external = state.links.filter(l => l.kind === 'openExternal');
    if (external.some(l => !l.web)) items.push({ status: 'confirmed', text: 'non-web links from content reach shell.openExternal (no scheme allowlist)' });
    else if (external.length) items.push({ status: 'todo', text: `links from content reach shell.openExternal: try ${forms.fileLink(state.platform)} to check the scheme allowlist` });
    const navigations = state.links.filter(l => l.kind === 'navigate');
    if (navigations.some(l => !l.prevented)) items.push({ status: 'confirmed', text: 'a link from content navigated an app window' });
    else if (navigations.length) items.push({ status: 'safe', text: 'navigation to the marker link was blocked' });
    const windows = state.links.filter(l => l.kind === 'window');
    if (windows.some(l => l.action !== 'deny')) items.push({ status: 'confirmed', text: 'a link from content opened a new app window' });
    else if (windows.length) items.push({ status: 'safe', text: 'new windows for the marker link were refused' });
    if (state.links.length === 0 && review.some(i => LINK_REVIEW.has(i.id))) items.push({ status: 'todo', text: `click the link ${forms.link} placed in shared content` });
    for (const p of state.paths) items.push({ status: 'confirmed', text: `a path from content was opened by shell.${p.method}` });
    for (const c of state.commands) items.push({ status: 'confirmed', text: `the marker reached a command line (${c.program})` });
    for (const [channel] of state.ipc) items.push({ status: 'info', text: `content reached IPC channel '${channel}'` });
    if (state.entries.has('paste-text') && !state.entries.has('paste-html')) items.push({ status: 'todo', text: 'paste formatted (HTML) content, not only plain text' });
    return items;
  }

  function printSummary(title = 'Validation so far') {
    const items = summary();
    if (items.length === 0) return;
    print(chalk.bold(`[validate] ${title}:`));
    const icon = { confirmed: chalk.red('✗ confirmed'), safe: chalk.green('✓ ruled out'), done: chalk.green('✓ done'), todo: chalk.cyan('→ to do'), info: chalk.yellow('! note') };
    for (const item of items) print(`[validate]   ${icon[item.status]}  ${item.text}`);
  }

  // The current session's channel for re-sending the marker request: confirm(question)->bool and send(command). Set at
  // the start of a session that can do this (an interactive terminal, a marker) and cleared when it ends.
  function useChannel(channel) { state.channel = channel || undefined; }
  function clearChannel() { state.channel = undefined; }

  return { intro, handle, summary, printSummary, useChannel, clearChannel };
}

/**
 * Follows a session log while the app runs and hands each new record to `onRecord`. Returns a function that stops
 * following (after reading what is left).
 */
export function followLog(file, onRecord, interval = 700) {
  let offset = 0;
  let rest = '';
  const read = () => {
    try {
      const size = fs.statSync(file).size;
      if (size <= offset) return;
      const fd = fs.openSync(file, 'r');
      try {
        const buffer = Buffer.alloc(size - offset);
        fs.readSync(fd, buffer, 0, buffer.length, offset);
        offset = size;
        const lines = (rest + buffer.toString('utf8')).split('\n');
        rest = lines.pop();
        for (const line of lines) {
          if (!line) continue;
          let record;
          try {
            record = JSON.parse(line);
          } catch {
            continue;
          }
          try {
            onRecord(record);
          } catch {
            // the assistant never stops the session
          }
        }
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      // not written yet
    }
  };
  const timer = setInterval(read, interval);
  if (timer.unref) timer.unref();
  return () => {
    clearInterval(timer);
    read();
  };
}
