#!/usr/bin/env node

import path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import pkg from '../package.json' with { type: 'json' };
import _i18n from './locales/i18n.js';
import run from './runner.js';
import { severity } from './finder/attributes.js';
import { OUTPUT_FORMATS } from './util/index.js';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { locateApp } from './watch/locate.js';
import { observeSession, collectRemote, parseHeaders } from './watch/session.js';
import { createAssistant, writeMarkerFiles } from './watch/assistant.js';
import { loadCampaign, hostsOutsideScope } from './watch/campaign.js';
import { isPackage, unpackTarget } from './unpack/index.js';
import { splitOutputs, unwritableOutput } from './util/file.js';
import { combineRuns, writeClientMarkdown, MARKDOWN_FOLDER } from './report/markdown.js';
import { createReportFolder, reportFiles } from './util/reportdir.js';

async function main() {

  if (process.argv.includes('--offline')) process.env.ELECTRONEGATIVITY_OFFLINE = '1';
  await _i18n(); // wait for the _i18n function to complete

  const VER = pkg.version;
  const falsyStrings = ["false", "FALSE", "off", "0", "no", "disable", "disabled"];

  const program = new Command();
  program
    .version(VER)
    .description(__('electronegativityDescription'))
    .option(__('inputOption'), __('inputOptionDescription'))
    .option(__('checksOption'), __('checksOptionDescription'))
    .option(__('excludeChecksOption'), __('excludeChecksOptionDescription'))
    .option(__('severityOption'), __('severityOptionDescription'))
    .option(__('confidenceOption'), __('confidenceOptionDescription'))
    .option(__('outputOption'), __('outputOptionDescription'))
    .option(__('relativeOption'), __('relativeOptionDescription'))
    .option(__('verboseOption'), __('verboseOptionDescription'))
    .option(__('upgradeOption'), __('upgradeOptionDescription'))
    .option(__('electronVersionOption'), __('electronVersionOptionDescription'))
    .option(__('parserPluginsOption'), __('parserPluginsOptionDescription'))
    .option('--offline', __('offlineOptionDescription'))
    .option('--all-files', __('allFilesOptionDescription'))
    .option('--baseline <file>', __('baselineOptionDescription'))
    .option('--write-baseline <file>', __('writeBaselineOptionDescription'))
    .option('--fail-on <severity>', __('failOnOptionDescription'))
    .option('--watch <app>', __('watchOptionDescription'))
    .option('--watch-args <args>', __('watchArgsOptionDescription'))
    .option('--watch-log <file>', __('watchLogOptionDescription'))
    .option('--watch-marker <token>', __('watchMarkerOptionDescription'))
    .option('--active-tests', 'Opt in to a benign HTML execution probe in watch mode; logs a nonce if the renderer executes it')
    .option('--campaign <file>', 'Run a bounded, profile-driven benign payload campaign without per-case prompts')
    .option('--auto-campaign', 'Capture a content save, suggest fields and a view, then ask before running a bounded campaign')
    .option('--debug-url <url>', 'Attach to an already running app through its local renderer DevTools endpoint, e.g. http://127.0.0.1:9222')
    .option('--debug-launch', 'Launch the app with an automatically selected local renderer debug port and attach; closes this launched app when observation ends')
    .option('--debug-target <id-or-url>', 'Select exactly one renderer target by ID or URL prefix when attaching')
    .option('--debug-duration <seconds>', 'Stop debug attachment after this many seconds; default waits for Ctrl+C')
    .option('--app <location>', __('appOptionDescription'))
    .option('--out <dir>', __('outOptionDescription'))
    .option('--report-dir [folder]', __('reportDirOptionDescription'))
    .option('--no-report-dir', __('noReportDirOptionDescription'))
    .option('--sessions <count>', __('sessionsOptionDescription'))
    .option('--no-watch-capture', __('watchCaptureOptionDescription'))
    .option('--remote <url>', __('remoteOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--remote-header <header>', __('remoteHeaderOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--ingest <file>', __('ingestOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--scope <domain>', __('scopeOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--no-watch-traffic', __('watchTrafficOptionDescription'))
    .option('--watch-screenshots [dir]', __('watchScreenshotsOptionDescription'))
    .option('--user-data <dir>', __('userDataOptionDescription'))
    .option('--canary <password>', __('canaryOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--search-dir <dir>', __('searchDirOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--show-secrets', __('showSecretsOptionDescription'))
    .option('--no-nvd', __('nvdOptionDescription'))
    .option('--finding-notes <file>', __('findingNotesOptionDescription'))
    .option('--suppress <file>', __('suppressOptionDescription'))
    .option('--compare <report>', __('compareOptionDescription'))
    .option('--diagnostics <file>', __('diagnosticsOptionDescription'))
    .option('--redact <terms>', __('redactOptionDescription'))
    .option('--share <file>', __('shareOptionDescription'))
    .option('--share-code', __('shareCodeOptionDescription'))
    .parse(process.argv);

  const options = program.opts();
  const campaign = options.campaign ? loadCampaign(options.campaign) : undefined;
  if ((options.activeTests || campaign || options.autoCampaign) && !options.watch && !options.app && !options.debugUrl) throw new Error('Active testing requires --watch, --app or --debug-url');
  if (options.autoCampaign && campaign) throw new Error('Choose --auto-campaign or --campaign, not both');
  if (options.autoCampaign && !process.stdin.isTTY) throw new Error('--auto-campaign needs an interactive terminal for approval; use an explicit --campaign profile for unattended runs');
  if (options.debugUrl && (!options.input && !options.app || options.watch || options.watchLog)) throw new Error('--debug-url requires -i or --app and cannot be combined with --watch or --watch-log');
  if (options.debugLaunch && ((!options.app && !options.watch) || options.debugUrl || options.watchLog)) throw new Error('--debug-launch requires --app or --watch and cannot be combined with --debug-url or --watch-log');
  if ((options.debugTarget || options.debugDuration) && !options.debugUrl && !options.debugLaunch) throw new Error('Debug target and duration require --debug-url or --debug-launch');
  const debug = { debugUrl: options.debugUrl, debugLaunch: !!options.debugLaunch, debugTarget: options.debugTarget, debugDuration: options.debugDuration === undefined ? 0 : Number(options.debugDuration) };
  if (!Number.isInteger(debug.debugDuration) || debug.debugDuration < 0 || debug.debugDuration > 86400) throw new Error('--debug-duration must be 0–86400 seconds');
  if ((options.activeTests || campaign || options.autoCampaign) && options.watchMarker && !/^[A-Za-z0-9_-]{8,80}$/.test(options.watchMarker)) throw new Error('Active testing requires a marker of 8–80 letters, digits, _ or -');
  const forCli = !options.output;

  if (forCli) {
    console.log(`
  ▄▄▄ ▄▄▌ ▄▄▄ .▄▄·▄▄▄▄▄▄▄
  ▀▄.▀██• ▀▄.▀▐█ ▌•██ ▀▄ █▪
  ▐▀▀▪██▪ ▐▀▀▪██ ▄▄▐█.▐▀▀▄ ▄█▀▄
  ▐█▄▄▐█▌▐▐█▄▄▐███▌▐█▌▐█•█▐█▌.▐▌
    ▀▀▀.▀▀▀ ▀▀▀·▀▀▀ ▀▀▀.▀  ▀▀█▄▀▪
    ▐ ▄▄▄▄ .▄▄ • ▄▄▄▄▄▄▄▪  ▌ ▐▪▄▄▄▄▄▄· ▄▌
  •█▌▐▀▄.▀▐█ ▀ ▐█ ▀•██ ██▪█·██•██ ▐█▪██▌
  ▐█▐▐▐▀▀▪▄█ ▀█▄█▀▀█▐█.▐█▐█▐█▐█▐█.▐█▌▐█▪
  ██▐█▐█▄▄▐█▄▪▐▐█ ▪▐▐█▌▐█▌███▐█▐█▌·▐█▀·.
  ▀▀ █▪▀▀▀·▀▀▀▀ ▀  ▀▀▀▀▀▀. ▀ ▀▀▀▀▀  ▀ •
        v`+VER+`  https://doyensec.com/
    `);
    console.log('\x1b[4m\x1b[36m%s\x1b[0m',__('tryElectroNgShort'));
    console.log("\x1b[4m\x1b[33m%s\x1b[0m", __('contactUs'));
    console.log("\x1b[4m\x1b[33m%s\x1b[0m", __('foundBug'));
    console.log(__('startScan'));
  }

  // Every run gets its own folder, electronegativity-<date and time>, made in the folder the tool was run from (or inside
  // --report-dir <folder>). --no-report-dir turns it off; --out (--app) names the results folder instead. A scan given
  // -o writes only those files (a CI job's checkout gets no extra reports), unless --report-dir is given as well.
  let reportFolder;
  const scanning = options.input || options.app || options.watch || options.watchLog || options.remote || options.ingest || options.userData || options.canary;
  const onlyOutputs = options.output && !options.app && program.getOptionValueSource('reportDir') !== 'cli';
  if (options.reportDir !== false && scanning && !options.out && !onlyOutputs) {
    const parent = typeof options.reportDir === 'string' ? options.reportDir : '.';
    try {
      reportFolder = createReportFolder(parent);
    } catch (error) {
      console.error(chalk.red(__('reportDirFailed', { dir: path.resolve(parent), reason: error.code || error.message })));
      process.exit(2);
    }
    // a run that ends before writing anything (bad input, nothing to scan) leaves no empty folder behind
    process.once('exit', () => { try { fs.rmdirSync(reportFolder); } catch { /* not empty, or already gone */ } });
    console.log(chalk.gray(__('reportFolder', { dir: reportFolder })));
    if (!options.app) {
      // what a scan writes there, unless asked for elsewhere: the report, the findings redacted for sharing, diagnostics
      const files = reportFiles(reportFolder);
      options.output = options.output ? `${options.output},${files.outputs.join(',')}` : files.outputs.join(',');
      options.share = [...(options.share ? [options.share] : []), ...files.shares];
      options.diagnostics = options.diagnostics || files.diagnostics;
    }
  }

  const watchArgs = options.watchArgs ? options.watchArgs.split(/\s+/).filter(Boolean) : [];
  const headers = parseHeaders(options.remoteHeader);
  const redact = options.redact ? options.redact.split(',').map(term => term.trim()).filter(Boolean) : [];
  const capture = options.watchCapture !== false;
  const traffic = options.watchTraffic !== false;
  const scope = (options.scope || []).flatMap(value => value.split(',')).map(value => value.trim()).filter(Boolean);
  // a campaign writes payloads to a backend: with --scope, only to the domains it names
  const outside = campaign ? hostsOutsideScope(campaign, scope) : [];
  if (outside.length > 0) {
    console.error(chalk.red(`--campaign would write to ${outside.join(', ')}, outside --scope ${scope.join(', ')}`));
    process.exit(2);
  }
  // --watch-screenshots alone: a screenshots folder in the current directory (or the --app results folder)
  const screenshots = options.watchScreenshots === true ? 'screenshots' : options.watchScreenshots;

  if (options.output) {
    // several outputs at once: -o report.html,report.json,report.docx,report.cdx.json (or space-separated, as an
    // unquoted comma list arrives from PowerShell)
    const outputs = splitOutputs(options.output);
    options.output = outputs.join(',');
    options.fileFormat = outputs.length === 1 ? outputs[0].split('.').pop().toLowerCase() : 'multiple';
    if (outputs.some(o => !OUTPUT_FORMATS.includes(o.split('.').pop().toLowerCase()))) {
      console.error(chalk.red(__('fileFormatError')));
      program.outputHelp();
      process.exit(1);
    }
    // before a scan or a watch session that can take a while: the reports must be writable where they go
    const unwritable = unwritableOutput([...outputs, ...[].concat(options.share || [])]);
    if (unwritable) {
      console.error(chalk.red(__('outputNotWritable', unwritable)));
      process.exit(2);
    }
  }
  if (options.share && !options.output && !options.app) {
    const unwritable = unwritableOutput([].concat(options.share));
    if (unwritable) {
      console.error(chalk.red(__('outputNotWritable', unwritable)));
      process.exit(2);
    }
  }
  let failOn;
  if (options.failOn) {
    failOn = severity[options.failOn.toUpperCase()];
    if (!failOn) {
      console.error(chalk.red(__('severityLevelError')));
      process.exit(2);
    }
  }
  // what every scan of this invocation shares
  const common = {
    customScan: options.checks ? options.checks.split(",").map(check => check.trim().toLowerCase()) : [],
    excludeFromScan: options.excludeChecks ? options.excludeChecks.split(",").map(check => check.trim().toLowerCase()) : [],
    severitySet: options.severity,
    confidenceSet: options.confidence,
    isRelative: options.relative,
    isVerbose: !(typeof options.verbose !== 'undefined' && falsyStrings.includes(options.verbose)),
    electronUpgrade: options.upgrade,
    electronVersionOverride: options.electronVersion,
    parserPlugins: options.parserPlugins ? options.parserPlugins.split(",").map(p => p.trim()) : [],
    offline: options.offline,
    allFiles: options.allFiles,
    baseline: options.baseline,
    writeBaseline: options.writeBaseline,
    redact,
    captures: options.ingest || [],
    scope,
    userData: options.userData,
    canaries: options.canary || [],
    searchDirs: options.searchDir || [],
    reveal: !!options.showSecrets,
    shareCode: !!options.shareCode,
    nvd: options.nvd !== false,
    findingNotes: options.findingNotes,
    suppress: options.suppress,
    compare: options.compare,
  };

  try {
    if (options.app) {
      await guided(options, common, { reportFolder, watchArgs, headers, capture, traffic, scope, screenshots, campaign, debug });
      return;
    }

    // Watch mode: run the app with the observation hook while the user goes through it, then analyze what happened
    let session;
    if (options.watch || options.watchLog || options.debugUrl) {
      try {
        session = await observeSession({ watch: options.debugUrl ? options.input : options.watch, watchLog: options.watchLog, args: watchArgs, ...debug, marker: options.watchMarker || ((options.activeTests || campaign || options.autoCampaign) ? generateMarker() : undefined), active: !!(options.activeTests || campaign || options.autoCampaign), campaign, autoCampaign: !!options.autoCampaign, capture, traffic, scope, screenshots,
          reveal: common.reveal, canaries: common.canaries, searchDirs: common.searchDirs, userData: common.userData, confirm: interactiveConfirm() });
      } catch (error) {
        console.error(chalk.red(error.message));
        process.exit(2);
      }
      if (!options.input && session.staticInput) options.input = session.staticInput;
    }
    // Front-end code served over the network: what watch mode captured, and --remote URLs. It is scanned with the app.
    const remote = await collectRemote({ runtime: session && session.runtime, watchLog: session && session.watchLog, capture, remote: options.remote || [], headers, scope, offline: options.offline });
    // --remote on its own: the downloaded front end is the input
    if (!options.input && remote.scanDir) options.input = remote.scanDir;

    // captures of the app's traffic, or a profile folder, on their own: nothing to scan statically
    if (!options.input && (options.ingest || options.userData || options.canary)) options.input = fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-no-code-'));

    if (!options.input) {
      program.outputHelp();
      process.exit(1);
    }

    // an installer or package (NSIS, Squirrel, .7z, .zip, .nupkg): unpacked to a temporary folder, whose app is scanned
    let installer;
    if (isPackage(options.input)) {
      try {
        installer = unpackTarget(options.input);
      } catch (error) {
        console.error(chalk.red(error.message));
        process.exit(2);
      }
      process.once('exit', () => installer.cleanup());
      if (forCli) console.log(chalk.green(__('installerUnpacked', { kind: installer.kind, file: options.input })));
      for (const warning of installer.warnings) console.error(chalk.yellow(warning));
      if (!installer.code) {
        console.error(chalk.red(__('installerNoApp')));
        process.exit(2);
      }
    }

    const result = await run({
      ...common,
      installer,
      input: installer ? installer.code : scanTarget(options.input),
      output: options.output,
      isSarif: options.fileFormat === 'sarif',
      runtimeElectronVersion: session && session.watchDiagnostics.electron,
      runtime: session && session.runtime,
      credentials: session && session.credentials,
      extraInputs: remote.extraInputs,
      remoteDiagnostics: remote.remoteDiagnostics,
      diagnostics: options.diagnostics,
      share: options.share,
      watchDiagnostics: session && session.watchDiagnostics,
    }, forCli);
    for (const file of [].concat(options.share || [])) if (!forCli) console.log(chalk.gray(__('shareWritten', { file })));
    // CI gate: fail when a reported finding reaches the given severity
    if (failOn) {
      const failing = result.reported.filter(issue => issue.severity.value >= failOn.value);
      if (failing.length > 0) {
        console.error(chalk.red(__('failOnTriggered', { count: failing.length, severity: failOn.name })));
        process.exitCode = 1;
      }
    }
  } catch (error) {
    console.error(chalk.red(error.stack));
    process.exit(1);
  }
}

// -i accepts an install folder or the app's executable too: the scan reads its resources\app.asar
function scanTarget(input) {
  try {
    const located = locateApp(input);
    return located.kind === 'project' ? path.resolve(input) : located.code;
  } catch {
    return path.resolve(input);
  }
}

// a token for planted content: letters and digits only, so it survives being used as text or an attribute name
function generateMarker() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'ENG' + [...crypto.randomBytes(6)].map(b => alphabet[b % alphabet.length]).join('');
}

async function ask(question, signal, preserveCase = false) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(question, signal ? { signal } : undefined)).trim();
    return preserveCase ? answer : answer.toLowerCase();
  } finally {
    rl.close();
  }
}

// A Y/N confirmation for the validation assistant (used only to re-send the marker request), enabled only when the
// terminal is interactive. The default is no: only an explicit "y" sends, so an accidental Enter (meant for the next
// prompt) never sends. Returns undefined when there is no interactive terminal, so the assistant falls back to telling
// the tester to send the request themselves. The returned function carries a cancel() that aborts an open question
// (used when the app closes with a question still waiting), which resolves it as no.
function interactiveConfirm() {
  if (!process.stdin.isTTY) return undefined;
  let active;
  const confirm = async (question) => {
    const controller = new AbortController();
    active = controller;
    try {
      const answer = await ask(question, controller.signal);
      return /^y/.test(answer); // empty answer (a bare Enter) means no
    } catch {
      return false; // cancelled (the session ended) or interrupted: treat as no
    } finally {
      if (active === controller) active = undefined;
    }
  };
  confirm.ask = async (question) => {
    const controller = new AbortController();
    active = controller;
    try { return await ask(question, controller.signal, true); }
    catch { return undefined; }
    finally { if (active === controller) active = undefined; }
  };
  confirm.cancel = () => { if (active) active.abort(); };
  return confirm;
}

function countBySeverity(issues) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const issue of issues) {
    const name = issue.severity.name;
    if (name === 'HIGH') counts.high++;
    else if (name === 'MEDIUM') counts.medium++;
    else if (name === 'LOW') counts.low++;
    else counts.info++;
  }
  return counts;
}

/**
 * --app <location>: finds the app, scans it statically, then runs as many watch sessions as the user wants (one per
 * account, typically), each with its own report and diagnostics file, all in one results folder.
 */
async function guided(options, common, { reportFolder, watchArgs, headers, capture, traffic, scope, screenshots, campaign, debug }) {
  const located = locateApp(options.app);
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
  const outDir = path.resolve(options.out || reportFolder || `electronegativity-results-${stamp}`);
  fs.mkdirSync(outDir, { recursive: true });
  console.log(chalk.green(__('appFound', { name: located.name, executable: located.executable || '-', code: located.code })));
  console.log(chalk.gray(__('appResults', { dir: outDir })));
  const written = [];
  // -o names the reports each step writes, prefixed with the step: static-report.html, session-1-components.xlsx...
  // (without -o, an HTML report per step). The client Markdown is written once, from every step: see the end.
  const requested = options.output ? splitOutputs(options.output) : [];
  const perStep = requested.filter(file => !/\.md$/i.test(file));
  const markdown = requested.length > perStep.length;
  const results = [];
  let lastOutputs = [];
  const step = async (name, extra) => {
    const outputs = perStep.length ? perStep.map(file => path.join(outDir, `${name}-${path.basename(file)}`)) : [path.join(outDir, `${name}.html`)];
    const output = outputs.find(file => /\.html?$/i.test(file)) || outputs[0];
    const diagnostics = path.join(outDir, `${name}-diag.json`);
    // --share: a redacted findings report per step, next to the others
    // (--report-dir: both Markdown and JSON)
    const shareTypes = options.share ? [/\.json$/i.test(options.share) ? '.json' : '.md'] : reportFolder || options.out ? ['.md', '.json'] : [];
    const shares = shareTypes.map(type => path.join(outDir, `${name}-share${type}`));
    const result = await run({ ...common, input: located.code, output: outputs, diagnostics, share: shares.length ? shares : undefined, ...extra }, false);
    written.push(...outputs, diagnostics, ...shares);
    results.push(result);
    lastOutputs = outputs;
    for (const error of result.errors.filter(e => !e.tolerable).slice(0, 5)) console.error(chalk.yellow(`${error.file}: ${error.message}`));
    console.log(chalk.green(__('appStepDone', { file: output, ...countBySeverity(result.reported) })));
    return result;
  };

  // 1. the app's code, including what's behind the login, and --remote URLs if given
  console.log(chalk.cyan(__('appStatic')));
  const remote = await collectRemote({ remote: options.remote || [], headers, scope, offline: options.offline });
  // the profile review and the password trace belong to the sessions, after the app has been used
  const staticResult = await step('static', { extraInputs: remote.extraInputs, remoteDiagnostics: remote.remoteDiagnostics, canaries: [], userData: undefined });

  // 2. watch sessions, until the user stops
  const interactive = !!process.stdin.isTTY;
  const sessions = options.sessions !== undefined ? Math.max(0, Number.parseInt(options.sessions, 10) || 0) : campaign || options.debugUrl || options.debugLaunch ? 1 : interactive ? Infinity : 0;
  const observable = located.executable || options.debugUrl;
  if (!observable && sessions > 0) console.error(chalk.yellow(__('appNoExecutable')));
  const marker = options.watchMarker || generateMarker();
  if (observable && sessions > 0) console.log(chalk.cyan(__('appMarker', { marker })));
  // one assistant for all sessions: what the static scan flagged for review, and what each session has shown so far
  let profileCount = 0;
  const assistant = createAssistant({ marker, active: !!(options.activeTests || campaign || options.autoCampaign), campaign, autoCampaign: !!options.autoCampaign, scope,
    saveCampaign: profile => { const file = path.join(outDir, `campaign-${++profileCount}.json`); fs.writeFileSync(file, JSON.stringify(profile, null, 2)); return file; },
    staticIssues: staticResult.issues, files: writeMarkerFiles(outDir, marker, !!(options.activeTests || campaign || options.autoCampaign)) });
  if (observable && sessions > 0) assistant.intro();
  for (let n = 1; observable && n <= sessions; n++) {
    if (interactive && options.sessions === undefined && !campaign && !options.debugUrl && !options.debugLaunch) {
      const answer = await ask(chalk.cyan(__(n === 1 ? 'appAskFirstSession' : 'appAskNextSession', { n })) + ' ');
      if (/^[snq]/.test(answer)) break;
    }
    let session;
    try {
      session = await observeSession({ watch: options.debugUrl ? located.folder : located.kind === 'project' ? located.folder : located.executable, args: watchArgs, ...debug, marker, active: !!(options.activeTests || campaign || options.autoCampaign), campaign, autoCampaign: !!options.autoCampaign, capture, traffic, scope,
        screenshots: screenshots && (path.isAbsolute(screenshots) ? screenshots : path.join(outDir, screenshots)),
        reveal: common.reveal, canaries: common.canaries, searchDirs: common.searchDirs, userData: common.userData, assistant, confirm: interactiveConfirm() });
    } catch (error) {
      console.error(chalk.red(error.message));
      process.exitCode = 1;
      break;
    }
    // the --remote-header goes to the --remote sites (and --scope domains) only, not to whatever the session captured
    const captured = await collectRemote({ runtime: session.runtime, watchLog: session.watchLog, capture, headers, headerSites: options.remote || [], scope, offline: options.offline });
    await step(`session-${n}`, { runtime: session.runtime, credentials: session.credentials, watchDiagnostics: session.watchDiagnostics, runtimeElectronVersion: session.watchDiagnostics.electron,
      extraInputs: captured.extraInputs, remoteDiagnostics: captured.remoteDiagnostics });
  }
  assistant.printSummary('Validation across all sessions');
  // the client findings of the whole run: the static scan and every session, each finding once, in one file per finding
  if (markdown) {
    const { reported, suppressed } = combineRuns(results);
    const files = writeClientMarkdown(outDir, reported, { app: results[0].app, root: located.code, suppressed, outputs: lastOutputs });
    written.push(`${path.join(outDir, MARKDOWN_FOLDER)} (${files.length} finding${files.length === 1 ? '' : 's'}, from ${results.length} step${results.length === 1 ? '' : 's'})`);
  }
  console.log(chalk.green(__('appDone', { dir: outDir })));
  for (const file of written) console.log(`  ${file}`);
}

main();
