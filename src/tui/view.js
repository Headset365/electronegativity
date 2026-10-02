import { Surface, THEMES, clip, tail, textWidth, wrapText } from './surface.js';

const TABS = ['Validation', 'App output', 'Tool logs', 'Findings'];
const statusColor = (status, palette) => ['ready', 'completed', 'connected'].includes(status) ? palette.good
  : ['error', 'incomplete', 'unavailable'].includes(status) ? palette.bad
    : ['running', 'reviewing', 'waiting'].includes(status) ? palette.warn : palette.subtle;

/** Draws the real terminal view; the model and input protocol do not depend on the theme. */
export function renderDashboard(ui, columns, rows, { color = true } = {}) {
  const width = Math.max(1, columns - 1), height = Math.max(1, rows);
  const p = THEMES[ui.themeIndex], screen = new Surface(width, height, p);
  ui.controls = [];
  const region = (id, x, y, w, h = 1, enabled = true, reason) => {
    if (x < 0 || y < 0 || x + w > width || y + h > height) return;
    ui.controls.push({ id, x: x + 1, y: y + 1, width: w, height: h, enabled, reason });
  };
  const button = (id, label, x, y, { primary = false, enabled = true, reason, width: size = textWidth(label) + 4, height: tall = 1 } = {}) => {
    const focused = ui.focus === id, hover = ui.hover === id;
    const bg = !enabled ? p.raised : primary ? hover ? p.text : p.accent : focused ? p.accent : hover ? p.border : p.raised;
    const fg = !enabled ? p.subtle : primary || focused ? p.onAccent : p.text;
    screen.fill(x, y, size, tall, bg);
    if (tall === 3) screen.panel(x, y, size, tall, { bg, border: focused ? p.text : bg });
    screen.text(x + Math.max(1, Math.floor((size - textWidth(label)) / 2)), y + Math.floor(tall / 2), label, { fg, bg, bold: enabled });
    if (focused) {
      screen.text(x + 1, y + Math.floor(tall / 2), '›', { fg, bg, bold: true });
      screen.text(x + size - 2, y + Math.floor(tall / 2), '‹', { fg, bg, bold: true });
    }
    region(id, x, y, size, tall, enabled, reason);
    return size;
  };
  if (width < 76 || height < 20) {
    screen.text(2, 1, '◇  ELECTRONEGATIVITY', { fg: p.accent, bold: true });
    screen.text(2, 3, 'Resize Windows Terminal to at least 77 columns × 20 rows.', { width: width - 4 });
    screen.text(2, 5, ui.phase, { fg: p.muted, width: width - 4 });
    screen.text(2, Math.min(8, height - 2), ui.finished ? 'Press Q to close.' : 'Your observation continues while the window is small.', { width: width - 4 });
    ui.surface = screen; return screen.lines(color);
  }

  const campaigns = [...ui.campaigns.entries()];
  const ready = campaigns.filter(([, item]) => item.status === 'ready' && item.session === ui.session).length;
  const running = campaigns.findLast(([, item]) => item.status === 'running')?.[1];
  const completed = campaigns.filter(([, item]) => item.status === 'completed').length;
  const prompt = ui.prompt;
  screen.text(2, 1, '◇', { fg: p.accent, bold: true });
  screen.text(5, 1, 'ELECTRONEGATIVITY', { bold: true });
  if (width >= 108) screen.text(24, 1, ' /  APPLICATION SECURITY', { fg: p.subtle });
  const state = ui.finished ? ui.exitCode ? 'RUN ENDED' : 'COMPLETE' : prompt ? 'YOUR NEXT STEP' : ui.live ? 'OBSERVING' : 'WORKING';
  screen.text(width - 35, 1, '● ' + state, { fg: ui.finished && ui.exitCode ? p.bad : prompt ? p.accent : ui.live ? p.good : p.muted, bold: true, width: 21 });
  button('theme', p.name + ' ◇', width - 14, 1, { width: 12 });
  screen.text(5, 2, clip(ui.target || 'Resolving application…', width - 10, true), { fg: p.muted });

  const roomy = height >= 28, metricHeight = roomy ? 4 : 3;
  const metrics = [
    ['FINDINGS', ui.counts ? String((ui.counts.high || 0) + (ui.counts.medium || 0) + (ui.counts.low || 0) + (ui.counts.info || 0)) : '—',
      ui.counts ? `${ui.counts.high || 0} high · ${ui.counts.medium || 0} medium` : 'Awaiting scan', ui.counts?.high ? p.bad : p.text],
    ['CAMPAIGNS', String(ready), 'ready · ' + completed + ' completed', ready ? p.good : p.text],
    ['SESSION', ui.session ? String(ui.session).padStart(2, '0') : '—', ui.live ? 'App is running' : ui.session ? 'Ready for review' : 'Static analysis', p.text],
    ['OBSERVER', ui.connection === 'connected' ? 'Connected' : ui.live ? 'Connecting' : 'Standby',
      ui.connection === 'connected' ? 'Runtime events flowing' : ui.live ? 'Waiting for app' : 'Starts with session', ui.connection === 'connected' ? p.good : p.muted],
  ];
  const gap = 1, metricWidth = Math.floor((width - 4 - gap * 3) / 4);
  metrics.forEach(([label, value, detail, fg], index) => {
    const x = 2 + index * (metricWidth + gap), w = index === 3 ? width - 2 - x : metricWidth;
    screen.fill(x, 4, w, metricHeight, p.panel);
    screen.text(x + 2, 4, label, { fg: p.subtle, width: w - 4 });
    screen.text(x + 2, 5, value, { fg, bold: true, width: w - 4 });
    if (roomy) screen.text(x + 2, 6, detail, { fg: p.muted, width: w - 4 });
  });
  const top = roomy ? 9 : 8, bottom = height - 4, bodyHeight = bottom - top;
  const left = Math.max(28, Math.min(40, Math.floor(width * 0.29))), mainX = left + 3, mainWidth = width - mainX - 2;
  ui.leftWidth = left + 2;
  const historyHeight = bodyHeight >= 17 ? 6 : 0, campaignHeight = bodyHeight - (historyHeight ? historyHeight + 1 : 0);
  screen.panel(1, top, left, campaignHeight, { title: 'Campaigns', subtitle: `${ready} ready`, focus: ui.focus === 'campaign-list' });
  region('campaign-list', 2, top + 1, left - 2, campaignHeight - 2);
  const slots = Math.max(1, Math.floor((campaignHeight - 2) / 5));
  const end = Math.max(1, campaigns.length - Math.min(ui.campaignScroll, Math.max(0, campaigns.length - 1)));
  const offerFor = item => [...ui.offers.values()].find(offer => offer.key === item.key && item.session === ui.session);
  const visible = campaigns.slice(Math.max(0, end - slots), end);
  let y = top + 2;
  for (const [key, item] of visible) {
    const offer = offerFor(item), enabled = !!offer && ui.live && !prompt && !ui.activeCampaign;
    const status = offer && ui.activeCampaign ? 'waiting' : item.status;
    const selected = ui.focus === `detail:${key}` || ui.hover === `detail:${key}`;
    if (selected) screen.fill(3, y - 1, left - 4, 4, p.raised);
    region(`detail:${key}`, 3, y - 1, left - 4, Math.min(4, top + campaignHeight - 1 - (y - 1)));
    screen.text(4, y - 1, '● ' + (status || 'waiting').toUpperCase(), { fg: statusColor(status, p), bold: true, width: left - 6 });
    screen.text(4, y, clip(item.key, left - 6, true), { width: left - 6, bold: true });
    const detail = status === 'running' && item.delivered !== undefined ? `${item.delivered} / ${item.cases || '?'} cases sent`
      : item.fields?.length ? `Fields: ${item.fields.join(', ')}` : item.reason || `${item.cases || '?'} cases · session ${item.session}`;
    screen.text(4, y + 1, clip(detail, left - 6, true), { fg: p.muted, width: left - 6 });
    if (offer && y + 2 < top + campaignHeight - 1)
      button(`campaign:${offer.id}`, 'Review & run', 4, y + 2, { primary: enabled, enabled, reason: 'Wait for the current action to finish before starting another campaign.' });
    else if (y + 2 < top + campaignHeight - 1) screen.text(4, y + 2, 'Click for details →', { fg: p.subtle, width: left - 6 });
    y += 5;
  }
  if (!visible.length) {
    screen.text(4, top + 2, '◇', { fg: p.accent });
    screen.text(4, top + 4, ui.campaignEnabled === false ? 'Campaigns are off' : 'Waiting for a capture', { bold: true, width: left - 6 });
    const hint = ui.campaignEnabled === false ? 'Enable auto-campaign to review captured saves here.'
      : ui.live ? 'Save a disposable record in the app. Eligible captures will appear here.' : 'Start a watch session, then save a disposable record in the app.';
    wrapText(hint, left - 6).slice(0, Math.max(0, campaignHeight - 7)).forEach((line, index) => screen.text(4, top + 6 + index, line, { fg: p.muted }));
  }
  if (historyHeight) {
    const historyY = top + campaignHeight + 1;
    screen.panel(1, historyY, left, historyHeight, { title: 'Sessions' });
    if (!ui.sessions.length) {
      screen.text(4, historyY + 2, '01  Static analysis', { fg: p.muted });
      screen.text(4, historyY + 3, 'Watch sessions follow your review.', { fg: p.subtle, width: left - 6 });
    } else ui.sessions.slice(-3).forEach((session, index) => {
      screen.text(4, historyY + 1 + index, `${session.number === ui.session ? '●' : '·'}  ${String(session.number).padStart(2, '0')}  ${session.state}`, {
        fg: session.state === 'Observing' ? p.good : p.muted, width: left - 6,
      });
    });
  }

  screen.panel(mainX, top, mainWidth, bodyHeight, { title: 'Workspace', subtitle: ui.scroll[ui.tab] ? 'HISTORY' : 'LIVE', focus: ui.focus === 'log' });
  const short = { Validation: 'Guide', 'App output': 'App', 'Tool logs': 'Tool', Findings: 'Findings' };
  let tabX = mainX + 2;
  for (const tab of TABS) {
    const label = mainWidth < 70 ? short[tab] : tab;
    const selected = ui.tab === tab, focused = ui.focus === `tab:${tab}` || ui.hover === `tab:${tab}`;
    const w = textWidth(label) + 2;
    screen.fill(tabX, top + 2, w, 1, selected ? p.raised : p.panel);
    screen.text(tabX + 1, top + 2, label, { fg: selected || focused ? p.accent : p.muted, bold: selected });
    screen.text(tabX, top + 3, selected ? '─'.repeat(w) : ' '.repeat(w), { fg: p.accent });
    region(`tab:${tab}`, tabX, top + 1, w, 3); tabX += w + 1;
  }
  const logX = mainX + 3, logWidth = mainWidth - 6;
  let logY = top + 5, logHeight = Math.max(1, bodyHeight - 7);
  if (ui.tab === 'Validation' && logHeight >= 10) {
    screen.fill(logX, logY, logWidth, 4, p.raised);
    for (let n = 0; n < 4; n++) screen.text(logX, logY + n, '▎', { fg: p.accent });
    const title = ui.finished ? 'Assessment complete' : ui.activeCampaign ? 'Campaign in progress' : ready ? `${ready} campaign${ready === 1 ? '' : 's'} ready to review`
      : ui.live ? ui.campaignEnabled ? 'Capture a content save' : 'Observe the app' : 'Analysis in progress';
    const hint = ui.finished ? 'Review your findings, then open the results folder.' : ui.activeCampaign ? 'Follow the active campaign in the sidebar. Other captures will wait.'
      : ready ? 'Choose Review & run in the sidebar. You will review fields and the saved view before approving.'
        : ui.live ? ui.campaignEnabled ? 'Save a disposable record in the app. Eligible captures appear in the sidebar.' : 'Use the app normally. Runtime evidence is collected as you work.'
          : 'Progress and findings appear as the tool examines your application.';
    screen.text(logX + 2, logY, title, { fg: p.accent, bold: true, width: logWidth - 4 });
    wrapText(hint, logWidth - 4).slice(0, 2).forEach((line, index) => screen.text(logX + 2, logY + 1 + index, line, { fg: p.muted }));
    screen.text(logX, logY + 5, 'VALIDATION ACTIVITY', { fg: p.subtle });
    logY += 7; logHeight -= 7;
  }
  const logLines = ui.logs[ui.tab].flatMap(line => wrapText(line, logWidth));
  ui.logWidths[ui.tab] = logWidth; ui.logCounts[ui.tab] = logLines.length;
  const logEnd = Math.max(0, logLines.length - ui.scroll[ui.tab]);
  const logVisible = logLines.slice(Math.max(0, logEnd - logHeight), logEnd);
  region('log', logX, logY, logWidth, logHeight);
  for (const [index, line] of logVisible.entries()) {
    const fg = /\b(HIGH|CRITICAL|error|failed)\b/i.test(line) ? p.bad : /\b(MEDIUM|warn|waiting)\b/i.test(line) ? p.warn
      : /\b(completed|verified|connected|ready|success)\b/i.test(line) ? p.good : ui.tab === 'App output' ? p.muted : p.text;
    screen.text(logX, logY + index, line, { fg, width: logWidth });
  }
  if (!logLines.length) {
    const empty = ui.tab === 'Findings' ? ['No findings to review yet', 'Findings appear here as analysis completes.']
      : ui.tab === 'App output' ? ['A quiet place for app output', 'Application and debug output will appear here.']
        : ui.tab === 'Tool logs' ? ['The tool is getting ready', 'Scan progress and diagnostics will appear here.']
          : ['Your next step appears here', 'Start a session to observe the app and review captured campaigns.'];
    screen.text(logX + 1, logY + Math.min(1, logHeight - 1), empty[0], { fg: p.text, bold: true, width: logWidth - 2 });
    wrapText(empty[1], logWidth - 2).slice(0, Math.max(0, logHeight - 3)).forEach((line, index) => screen.text(logX + 1, logY + 3 + index, line, { fg: p.muted }));
  }
  if (logLines.length > logHeight) {
    const track = logHeight, thumb = Math.max(1, Math.round(track * logHeight / logLines.length));
    const at = Math.round((track - thumb) * Math.min(1, logEnd / logLines.length));
    for (let n = 0; n < track; n++) screen.text(mainX + mainWidth - 2, logY + n, n >= at && n < at + thumb ? '┃' : '│', { fg: n >= at && n < at + thumb ? p.accent : p.border });
  }

  screen.text(3, bottom + 1, clip(running ? `Campaign running · ${running.delivered || 0}/${running.cases || '?'} cases sent` : ui.phase, width - 36, true), { fg: p.muted });
  const actions = ui.finished ? [...(ui.folder ? [['folder', 'Open results']] : []), ['quit', 'Close']]
    : ui.live ? [['end-session', 'End session']] : [];
  let actionX = width - 2 - actions.reduce((sum, [, label]) => sum + textWidth(label) + 5, 0);
  for (const [id, label] of actions) actionX += button(id, label, actionX, bottom + 1, { primary: id === 'folder' }) + 1;
  screen.text(3, height - 2, clip(ui.notice, width - 6, true), { fg: p.accent });
  screen.fill(0, height - 1, width, 1, p.panel);
  screen.text(3, height - 1, 'Tab', { fg: p.accent, bold: true }); screen.text(7, height - 1, ' select   Enter', { fg: p.muted });
  screen.text(21, height - 1, ' act   PgUp/PgDn', { fg: p.muted }); screen.text(38, height - 1, ' scroll   Esc', { fg: p.muted });
  screen.text(51, height - 1, ' cancel   T theme', { fg: p.muted });
  if (width >= 98) screen.text(width - 27, height - 1, 'Ctrl+C  end session', { fg: p.muted });

  if (prompt) {
    screen.dim(); ui.controls = [];
    const isDetails = prompt.kind === 'details', session = prompt.kind === 'session', text = prompt.kind === 'text';
    const modalWidth = Math.min(width - 8, text || isDetails ? 82 : 76);
    const content = session ? wrapText(ui.session ? `Session ${ui.session} has ended. Review the evidence, then choose what comes next.`
      : 'Your static analysis is ready. Start a watch session to observe the app, or finish and write your reports.', modalWidth - 8)
      : wrapText(String(prompt.question || '').replace(/^\[validate\]\s*/, ''), modalWidth - 8);
    const desired = Math.max(session ? 15 : text ? 17 : 13, content.length + (text ? 15 : 12));
    const modalHeight = Math.min(height - 4, desired), modalX = Math.floor((width - modalWidth) / 2), modalY = Math.floor((height - modalHeight) / 2);
    screen.fill(modalX + 1, modalY + 1, modalWidth, modalHeight, p.bg);
    screen.panel(modalX, modalY, modalWidth, modalHeight, { border: p.accent, bg: p.panel });
    const title = session ? 'Choose your next step' : isDetails ? 'Campaign details' : text ? /Fields to test/i.test(prompt.question) ? 'Choose content fields'
      : /Saved-content view/i.test(prompt.question) ? 'Choose the saved view' : 'Your input is needed' : 'Review & approve';
    screen.text(modalX + 4, modalY + 2, title, { bold: true, fg: p.text });
    screen.text(modalX + 4, modalY + 3, session ? 'SESSION REVIEW' : isDetails ? 'CAPTURE INSPECTOR' : text ? 'CAMPAIGN SETUP' : 'EXPLICIT APPROVAL', { fg: p.accent });
    const contentHeight = Math.max(1, modalHeight - (text ? 15 : 12)), contentY = modalY + 5;
    ui.promptLines = content.length; ui.promptPage = contentHeight;
    ui.promptScroll = Math.max(0, Math.min(ui.promptScroll, Math.max(0, content.length - contentHeight)));
    content.slice(ui.promptScroll, ui.promptScroll + contentHeight).forEach((line, index) => screen.text(modalX + 4, contentY + index, line, { fg: p.muted, width: modalWidth - 8 }));
    region('prompt-scroll', modalX + 3, contentY, modalWidth - 6, contentHeight);
    if (content.length > contentHeight) screen.text(modalX + 4, contentY + contentHeight, '↑↓ / wheel to read more', { fg: p.accent });
    const buttonY = modalY + modalHeight - 5;
    if (text) {
      const fieldY = buttonY - 3, focused = ui.focus === 'input';
      screen.panel(modalX + 4, fieldY - 1, modalWidth - 8, 3, { bg: p.raised, border: focused ? p.accent : p.border });
      const value = ui.input || 'Click here to type · blank uses the suggested value';
      // Show the end of a long value, preserving grapheme/cell boundaries.
      const displayed = tail(value, modalWidth - 14);
      screen.text(modalX + 6, fieldY, displayed + (focused ? '▏' : ''), { fg: ui.input ? p.text : p.subtle, width: modalWidth - 12 });
      region('input', modalX + 4, fieldY - 1, modalWidth - 8, 3);
    }
    if (session) {
      const first = button('session-start', 'Start next session', modalX + 4, buttonY, { primary: true, height: 3 });
      button('session-finish', 'Finish & write reports', modalX + 6 + first, buttonY, { height: 3 });
    } else {
      button('cancel', isDetails ? 'Back' : 'Cancel', modalX + 4, buttonY, { height: 3 });
      const item = isDetails ? ui.campaigns.get(prompt.campaignKey) : undefined, offer = item && offerFor(item);
      if (!isDetails || offer) {
        const label = isDetails ? 'Review & run' : text ? 'Use value / default' : 'Approve';
        button(isDetails ? 'detail-run' : text ? 'submit' : 'approve', label, modalX + modalWidth - textWidth(label) - 8, buttonY,
          { primary: true, height: 3, enabled: !isDetails || !!offer && ui.live && !ui.activeCampaign, reason: 'A campaign is already active, or this session has ended.' });
      }
    }
    screen.text(modalX + 4, modalY + modalHeight - 2, clip(session ? 'Nothing starts until you choose a button.' : text ? 'Select the field to type. Submit explicitly.' : 'Tab to choose · Enter to act · Esc to go back', modalWidth - 8), { fg: p.subtle });
  } else { ui.promptLines = 0; ui.promptScroll = 0; }
  ui.surface = screen;
  return screen.lines(color);
}
