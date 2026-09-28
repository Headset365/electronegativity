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
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { locateApp } from './watch/locate.js';
import { observeSession, collectRemote, parseHeaders } from './watch/session.js';
import { createAssistant, writeMarkerFiles } from './watch/assistant.js';

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
    .option('--app <location>', __('appOptionDescription'))
    .option('--out <dir>', __('outOptionDescription'))
    .option('--sessions <count>', __('sessionsOptionDescription'))
    .option('--no-watch-capture', __('watchCaptureOptionDescription'))
    .option('--remote <url>', __('remoteOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--remote-header <header>', __('remoteHeaderOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--diagnostics <file>', __('diagnosticsOptionDescription'))
    .option('--redact <terms>', __('redactOptionDescription'))
    .parse(process.argv);

  const options = program.opts();
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

  const watchArgs = options.watchArgs ? options.watchArgs.split(/\s+/).filter(Boolean) : [];
  const headers = parseHeaders(options.remoteHeader);
  const redact = options.redact ? options.redact.split(',').map(term => term.trim()).filter(Boolean) : [];
  const capture = options.watchCapture !== false;

  if (options.output) {
    options.fileFormat = options.output.split('.').pop().toLowerCase();
    if (!OUTPUT_FORMATS.includes(options.fileFormat)) {
      console.error(chalk.red(__('fileFormatError')));
      program.outputHelp();
      process.exit(1);
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
  };

  try {
    if (options.app) {
      await guided(options, common, { watchArgs, headers, capture });
      return;
    }

    // Watch mode: run the app with the observation hook while the user goes through it, then analyze what happened
    let session;
    if (options.watch || options.watchLog) {
      try {
        session = await observeSession({ watch: options.watch, watchLog: options.watchLog, args: watchArgs, marker: options.watchMarker, capture, confirm: interactiveConfirm() });
      } catch (error) {
        console.error(chalk.red(error.message));
        process.exit(2);
      }
      if (!options.input && session.staticInput) options.input = session.staticInput;
    }
    // Front-end code served over the network: what watch mode captured, and --remote URLs. It is scanned with the app.
    const remote = await collectRemote({ runtime: session && session.runtime, watchLog: session && session.watchLog, capture, remote: options.remote || [], headers, offline: options.offline });
    // --remote on its own: the downloaded front end is the input
    if (!options.input && remote.scanDir) options.input = remote.scanDir;

    if (!options.input) {
      program.outputHelp();
      process.exit(1);
    }

    const result = await run({
      ...common,
      input: scanTarget(options.input),
      output: options.output,
      isSarif: options.fileFormat === 'sarif',
      runtimeElectronVersion: session && session.watchDiagnostics.electron,
      runtime: session && session.runtime,
      extraInputs: remote.extraInputs,
      remoteDiagnostics: remote.remoteDiagnostics,
      diagnostics: options.diagnostics,
      watchDiagnostics: session && session.watchDiagnostics,
    }, forCli);
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

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim().toLowerCase();
  } finally {
    rl.close();
  }
}

// A Y/N confirmation for the validation assistant (used only to re-send the marker request), enabled only when the
// terminal is interactive. An empty answer means yes. Returns undefined when there is no interactive terminal, so the
// assistant falls back to telling the tester to send the request themselves.
function interactiveConfirm() {
  if (!process.stdin.isTTY) return undefined;
  return async (question) => {
    const answer = await ask(question);
    return answer === '' || /^y/.test(answer);
  };
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
async function guided(options, common, { watchArgs, headers, capture }) {
  const located = locateApp(options.app);
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
  const outDir = path.resolve(options.out || `electronegativity-results-${stamp}`);
  fs.mkdirSync(outDir, { recursive: true });
  console.log(chalk.green(__('appFound', { name: located.name, executable: located.executable || '-', code: located.code })));
  console.log(chalk.gray(__('appResults', { dir: outDir })));
  const written = [];
  const step = async (name, extra) => {
    const output = path.join(outDir, `${name}.html`);
    const diagnostics = path.join(outDir, `${name}-diag.json`);
    const result = await run({ ...common, input: located.code, output, diagnostics, ...extra }, false);
    written.push(output, diagnostics);
    for (const error of result.errors.filter(e => !e.tolerable).slice(0, 5)) console.error(chalk.yellow(`${error.file}: ${error.message}`));
    console.log(chalk.green(__('appStepDone', { file: output, ...countBySeverity(result.reported) })));
    return result;
  };

  // 1. the app's code, including what's behind the login, and --remote URLs if given
  console.log(chalk.cyan(__('appStatic')));
  const remote = await collectRemote({ remote: options.remote || [], headers, offline: options.offline });
  const staticResult = await step('static', { extraInputs: remote.extraInputs, remoteDiagnostics: remote.remoteDiagnostics });

  // 2. watch sessions, until the user stops
  const interactive = !!process.stdin.isTTY;
  const sessions = options.sessions !== undefined ? Math.max(0, Number.parseInt(options.sessions, 10) || 0) : interactive ? Infinity : 0;
  if (!located.executable && sessions > 0) console.error(chalk.yellow(__('appNoExecutable')));
  const marker = options.watchMarker || generateMarker();
  if (located.executable && sessions > 0) console.log(chalk.cyan(__('appMarker', { marker })));
  // one assistant for all sessions: what the static scan flagged for review, and what each session has shown so far
  const assistant = createAssistant({ marker, staticIssues: staticResult.issues, files: writeMarkerFiles(outDir, marker) });
  if (located.executable && sessions > 0) assistant.intro();
  for (let n = 1; located.executable && n <= sessions; n++) {
    if (options.sessions === undefined) {
      const answer = await ask(chalk.cyan(__(n === 1 ? 'appAskFirstSession' : 'appAskNextSession', { n })) + ' ');
      if (/^[snq]/.test(answer)) break;
    }
    let session;
    try {
      session = await observeSession({ watch: located.kind === 'project' ? located.folder : located.executable, args: watchArgs, marker, capture, assistant, confirm: interactiveConfirm() });
    } catch (error) {
      console.error(chalk.red(error.message));
      break;
    }
    const captured = await collectRemote({ runtime: session.runtime, watchLog: session.watchLog, capture, headers, offline: options.offline });
    await step(`session-${n}`, { runtime: session.runtime, watchDiagnostics: session.watchDiagnostics, runtimeElectronVersion: session.watchDiagnostics.electron,
      extraInputs: captured.extraInputs, remoteDiagnostics: captured.remoteDiagnostics });
  }
  assistant.printSummary('Validation across all sessions');
  console.log(chalk.green(__('appDone', { dir: outDir })));
  for (const file of written) console.log(`  ${file}`);
}

main();
