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
import { observeSession, collectRemote } from './watch/session.js';
import remoteHosts from './remote/hosts.cjs';
import { createAssistant, writeMarkerFiles } from './watch/assistant.js';
import { campaignPlan } from './watch/campaign_plan.js';
import { loadCampaign, hostsOutsideScope } from './watch/campaign.js';
import { isPackage, unpackTarget } from './unpack/index.js';
import { splitOutputs, unwritableOutput } from './util/file.js';
import { writeCombinedReport } from './report/combined.js';
import { rerender } from './report/rerender.js';
import { createReportFolder, reportFiles } from './util/reportdir.js';
import { createRequire } from 'node:module';
import { isTuiWorker, interactiveTerminal, tuiAsk, tuiConfirm, tuiEvent } from './tui/bridge.js';
const { loadProfile } = createRequire(import.meta.url)('./watch/proof-profile.cjs');

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
    .option(__('outputOption').replace('<filename>', '<filenames...>'), __('outputOptionDescription'))
    .option(__('relativeOption'), __('relativeOptionDescription'))
    .option(__('verboseOption'), __('verboseOptionDescription'))
    .option(__('upgradeOption'), __('upgradeOptionDescription'))
    .option(__('electronVersionOption'), __('electronVersionOptionDescription'))
    .option(__('parserPluginsOption'), __('parserPluginsOptionDescription'))
    .option('--offline', __('offlineOptionDescription'))
    .option('--tui', 'Windows PowerShell dashboard with separate logs, campaign controls and session review')
    .option('--all-files', __('allFilesOptionDescription'))
    .option('--baseline <file>', __('baselineOptionDescription'))
    .option('--write-baseline <file>', __('writeBaselineOptionDescription'))
    .option('--fail-on <severity>', __('failOnOptionDescription'))
    .option('--watch <app>', __('watchOptionDescription'))
    .option('--watch-args <args>', __('watchArgsOptionDescription'))
    .option('--watch-log <file>', __('watchLogOptionDescription'))
    .option('--watch-marker <token>', __('watchMarkerOptionDescription'))
    .option('--active-tests', 'Opt in to a benign HTML execution probe in watch mode; logs a nonce if the renderer executes it')
    .option('--prove', 'Opt in to bounded native-watch handler, self-signed TLS and Windows RunAsNode proofs')
    .option('--proof-profile <file>', 'With --prove: exact origins, update feeds and reviewed link/service routes')
    .option('--ipc-profile <file>', 'Separate opt-in: reviewed read-only IPC contracts and tool-owned file canaries')
    .option('--logout-check', 'Capture live before/after logout snapshots using interactive BEFORE and AFTER checkpoints')
    .option('--campaign <file>', 'Run a bounded, profile-driven benign payload campaign without per-case prompts')
    .option('--no-source-maps', 'Keep packaged bundle analysis instead of recovering embedded original sources')
    .option('--campaign-plan <file>', 'Export finding-linked campaign drafts to review and complete before execution')
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
    // several values, comma- or space-separated: --remote a.example.com, b.example.com --remote-header Authorization, Cookie
    .option('--remote <hosts...>', __('remoteOptionDescription'), (value, previous) => [...(previous || []), value])
    .option('--remote-header <names...>', __('remoteHeaderOptionDescription'), (value, previous) => [...(previous || []), value])
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
    .option('--rerender <report.json>', 'write the client findings of an earlier scan again with the current templates, from its report.json, into a newReports subfolder of its findings folder (tester notes in newTesterNotes); manual edits in the earlier findings are listed in newReports-review.md')
    .option('--old-reports <folder>', 'with --rerender: the folder of the earlier findings (default: the reports folder next to report.json)')
    .parse(process.argv);

  const options = program.opts();
  // Windows PowerShell versions can pass an unquoted comma list as one spaced value or several native arguments.
  if (options.output) options.output = splitOutputs(options.output).join(',');
  if (options.tui && !isTuiWorker) {
    const { runDashboard } = await import('./tui/dashboard.js');
    const result = await runDashboard(process.argv.slice(2));
    process.exitCode = result.code;
    console.log(`Electronegativity dashboard closed (exit code ${result.code}).`);
    if (result.folder) console.log(`Results: ${result.folder}`);
    return;
  }
  tuiEvent('configuration', { target: options.app || options.watch || options.input || options.rerender,
    autoCampaign: !!options.autoCampaign, campaign: !!options.campaign, mode: options.app ? 'guided' : options.watch ? 'watch' : 'scan' });
  tuiEvent('phase', { text: options.rerender ? 'Rewriting reports…' : 'Checking command options…' });
  // --rerender: no scan, only the earlier scan's findings written again
  if (options.rerender) {
    try {
      if (!options.offline) console.log(chalk.gray('Checking the links of the components workbook again...'));
      const result = await rerender({ dataFile: options.rerender, oldDir: options.oldReports, version: VER, checkLinks: !options.offline });
      const edited = result.compared.filter(c => c.known && c.changes.length).length;
      const unknown = result.compared.filter(c => !c.known && c.changes.length).length;
      console.log(chalk.green(`${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} and the components workbook written to ${result.dir}, the tester notes to ${result.notesDir}`));
      if (result.workbook) {
        const changedLinks = result.workbook.rows.filter(r => !/no change\.$/.test(r.text)).length;
        console.log(chalk.gray(result.workbook.checked ? `Workbook links checked again: ${changedLinks} of ${result.workbook.rows.length} component${result.workbook.rows.length === 1 ? '' : 's'} changed (see the "Changes since the earlier workbook" column)`
          : 'Workbook links not checked again (--offline)'));
      }
      console.log(chalk[edited || unknown ? 'yellow' : 'gray'](`${edited} earlier finding${edited === 1 ? '' : 's'} edited by hand${unknown ? `, ${unknown} that may have been (written before edits could be told apart)` : ''}: see ${result.review}`));
    } catch (error) {
      console.error(chalk.red(error.message));
      process.exit(2);
    }
    return;
  }
  const campaign = options.campaign ? loadCampaign(options.campaign) : undefined;
  const proofProfile = options.proofProfile ? loadProfile(options.proofProfile) : undefined;
  const ipcProfile = options.ipcProfile ? loadProfile(options.ipcProfile, true) : undefined;
  if (options.proofProfile && !options.prove) throw new Error('--proof-profile requires --prove');
  if ((options.prove || ipcProfile || options.logoutCheck) && ((!options.watch && !options.app) || options.watchLog || options.debugUrl || options.debugLaunch))
    throw new Error('Proof and logout options require --watch or --app in native watch mode');
  if (options.logoutCheck && !interactiveTerminal()) throw new Error('--logout-check requires an interactive terminal');
  if (options.logoutCheck && options.autoCampaign) throw new Error('Use separate sessions for --logout-check and --auto-campaign');
  if ((options.activeTests || campaign || options.autoCampaign) && !options.watch && !options.app && !options.debugUrl) throw new Error('Active testing requires --watch, --app or --debug-url');
  if (options.autoCampaign && campaign) throw new Error('Choose --auto-campaign or --campaign, not both');
  if (options.autoCampaign && !interactiveTerminal()) throw new Error('--auto-campaign needs an interactive terminal for approval; use an explicit --campaign profile for unattended runs');
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
        v`+VER+`  https://github.com/Headset365/electronegativity
    `);
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
    tuiEvent('results-folder', { folder: reportFolder });
    if (!options.app) {
      // what a scan writes there, unless asked for elsewhere: the report, the findings redacted for sharing, diagnostics
      const files = reportFiles(reportFolder);
      options.output = options.output ? `${options.output},${files.outputs.join(',')}` : files.outputs.join(',');
      options.share = [...(options.share ? [options.share] : []), ...files.shares];
      options.diagnostics = options.diagnostics || files.diagnostics;
    }
  }

  const watchArgs = options.watchArgs ? options.watchArgs.split(/\s+/).filter(Boolean) : [];
  // --remote: the only hosts the tool fetches from itself; --remote-header: names to copy from the app's requests to
  // them, or 'Name: value' headers set by hand
  const remote = remoteHosts.parseRemote(options.remote);
  const remoteHeaders = remoteHosts.parseRemoteHeaders(options.remoteHeader);
  if (remote.invalid.length > 0 || remoteHeaders.invalid.length > 0) {
    if (remote.invalid.length > 0) console.error(chalk.red(`--remote takes host names (app.example.com, *.example.com) or URLs: ${remote.invalid.join(', ')}`));
    if (remoteHeaders.invalid.length > 0) console.error(chalk.red(`--remote-header takes header names (Authorization, Cookie) or 'Name: value': ${remoteHeaders.invalid.join(', ')}`));
    process.exit(2);
  }
  if (remoteHeaders.names.length > 0 && remote.hosts.length === 0) {
    console.error(chalk.red(`--remote-header ${remoteHeaders.names.join(', ')}: the values are copied from what the app sends to the --remote hosts; name them, e.g. --remote app.example.com`));
    process.exit(2);
  }
  if (remoteHeaders.names.length > 0 && !options.watch && !options.app && !options.debugUrl)
    console.error(chalk.yellow(`--remote-header ${remoteHeaders.names.join(', ')}: values are only copied while the app runs (--app or --watch); the download goes without them`));
  const headers = remoteHeaders.fixed;
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
    onProgress: isTuiWorker ? ({ done, total, phase }) => tuiEvent('phase', { text: phase || `Scanning files: ${done}/${total}` }) : undefined,
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
    sourceMaps: options.sourceMaps,
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
      const result = await guided(options, common, { reportFolder, watchArgs, headers, remote, headerNames: remoteHeaders.names, capture, traffic, scope, screenshots, campaign, debug });
      applySeverityGate(result.reported, failOn);
      return;
    }

    // Watch mode: run the app with the observation hook while the user goes through it, then analyze what happened
    let session;
    if (options.watch || options.watchLog || options.debugUrl) {
      try {
        if (!options.watchLog) tuiEvent('session-start', { number: 1 });
        session = await observeSession({ watch: options.debugUrl ? options.input : options.watch, watchLog: options.watchLog, args: watchArgs, ...debug, marker: options.watchMarker || ((options.activeTests || campaign || options.autoCampaign) ? generateMarker() : undefined), active: !!(options.activeTests || campaign || options.autoCampaign), campaign, autoCampaign: !!options.autoCampaign, capture, traffic, scope, screenshots,
          prove: !!options.prove, proofProfile, ipcProfile, logout: !!options.logoutCheck,
          reveal: common.reveal, canaries: common.canaries, searchDirs: common.searchDirs, userData: common.userData, confirm: interactiveConfirm(),
          remoteHosts: remote.hosts, headerNames: remoteHeaders.names });
      } catch (error) {
        console.error(chalk.red(error.message));
        process.exit(2);
      }
      if (!options.input && session.staticInput) options.input = session.staticInput;
    }
    // Front-end code served over the network: what watch mode captured, and --remote URLs. It is scanned with the app.
    tuiEvent('phase', { text: 'Collecting remote sources and scanning…' });
    const fetched = await collectRemote({ runtime: session && session.runtime, watchLog: session && session.watchLog, capture, remote: remote.seeds, guessed: remote.guessed, headers, scope,
      allowHosts: remote.hosts, headersByHost: (session && session.copiedHeaders) || {}, offline: options.offline });
    // --remote on its own: the downloaded front end is the input
    if (!options.input && fetched.scanDir) options.input = fetched.scanDir;

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
      sourceMaps: options.sourceMaps,
      extraInputs: fetched.extraInputs,
      remoteDiagnostics: fetched.remoteDiagnostics,
      diagnostics: options.diagnostics,
      share: options.share,
      watchDiagnostics: session && session.watchDiagnostics,
      // nothing written anywhere else: the client findings and components workbook go to reports/ where the tool ran
      reportsBase: process.cwd(),
    }, forCli);
    publishFindings(result);
    if (!reportFolder && options.output) tuiEvent('results-folder', { folder: path.dirname(path.resolve(splitOutputs(options.output)[0])) });
    for (const file of [].concat(options.share || [])) if (!forCli) console.log(chalk.gray(__('shareWritten', { file })));
    if (options.campaignPlan) writeCampaignPlan(options.campaignPlan, result.issues);
    // CI gate: fail when a reported finding reaches the given severity
    applySeverityGate(result.reported, failOn);
  } catch (error) {
    console.error(chalk.red(error.stack));
    process.exit(1);
  }
}

function applySeverityGate(reported, failOn) {
  if (!failOn) return;
  const failing = reported.filter(issue => issue.severity.value >= failOn.value);
  if (failing.length > 0) {
    console.error(chalk.red(__('failOnTriggered', { count: failing.length, severity: failOn.name })));
    process.exitCode = 1;
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

async function ask(question, signal, preserveCase = false, kind = 'text') {
  if (isTuiWorker) {
    const answer = await tuiAsk(question, { signal, kind });
    if (answer === undefined) return undefined;
    return preserveCase ? answer.trim() : answer.trim().toLowerCase();
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    // App/debugger output can arrive while awaiting input. Keep the full question in terminal history.
    process.stdout.write(`\n${question.trim()}\n`);
    const answer = (await rl.question('> ', signal ? { signal } : undefined)).trim();
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
  if (isTuiWorker) return tuiConfirm();
  if (!interactiveTerminal()) return undefined;
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
 * account, typically). Each step's reports are kept in steps/ as backups; at the end, one report of the whole run (the
 * static findings with what each session validated, and what the sessions found), its client findings and components
 * workbook in reports/, and one diagnostics file, all in one results folder.
 */
async function guided(options, common, { reportFolder, watchArgs, headers, remote, headerNames, capture, traffic, scope, screenshots, campaign, debug }) {
  const located = locateApp(options.app);
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
  const outDir = path.resolve(options.out || reportFolder || `electronegativity-results-${stamp}`);
  fs.mkdirSync(outDir, { recursive: true });
  console.log(chalk.green(__('appFound', { name: located.name, executable: located.executable || '-', code: located.code })));
  console.log(chalk.gray(__('appResults', { dir: outDir })));
  tuiEvent('results-folder', { folder: outDir });
  // -o names the reports of the run (report.html, report.docx...; the .md is the reports/ folder, always written): the final
  // ones in the results folder, and each step's backups in steps/, prefixed with the step (static-report.html,
  // session-1-report.html). Without -o: report.html and report.json.
  const requested = options.output ? splitOutputs(options.output).filter(file => !/\.md$/i.test(file)) : [];
  const finalOutputs = (requested.length ? requested : ['report.html', 'report.json']).map(file => path.join(outDir, path.basename(file)));
  const stepsDir = path.join(outDir, 'steps');
  fs.mkdirSync(stepsDir, { recursive: true });
  // --share: a redacted findings report (--report-dir and --out: both Markdown and JSON)
  const shareTypes = options.share ? [/\.json$/i.test(options.share) ? '.json' : '.md'] : reportFolder || options.out ? ['.md', '.json'] : [];
  const results = [];
  const stepNames = [];
  const stepDiagnostics = [];
  const step = async (name, extra) => {
    const outputs = finalOutputs.map(file => path.join(stepsDir, `${name}-${path.basename(file)}`));
    const output = outputs.find(file => /\.html?$/i.test(file)) || outputs[0];
    const diagnostics = path.join(stepsDir, `${name}-diag.json`);
    const shares = shareTypes.map(type => path.join(stepsDir, `${name}-share${type}`));
    // the client findings and components workbook are written once, for the whole run
    const result = await run({ ...common, input: located.code, output: outputs, diagnostics, share: shares.length ? shares : undefined, reports: false, ...extra }, false);
    results.push(result);
    stepNames.push(name);
    stepDiagnostics.push({ name, file: diagnostics });
    for (const error of result.errors.filter(e => !e.tolerable).slice(0, 5)) console.error(chalk.yellow(`${error.file}: ${error.message}`));
    console.log(chalk.green(__('appStepDone', { file: output, ...countBySeverity(result.reported) })));
    publishFindings(result, name);
    return result;
  };

  const interactive = interactiveTerminal();
  const sessions = options.sessions !== undefined ? Math.max(0, Number.parseInt(options.sessions, 10) || 0) : isTuiWorker ? Infinity : campaign || options.prove || options.ipcProfile || options.logoutCheck || options.debugUrl || options.debugLaunch ? 1 : interactive ? Infinity : 0;
  const observable = located.executable || options.debugUrl;
  // --remote-header names: nothing to copy before the app has run, so the --remote sites are downloaded after each
  // session, with the values it sent (there are no sessions: now, without them)
  const afterSessions = headerNames.length > 0 && !!observable && sessions > 0;

  // 1. the app's code, including what's behind the login, and --remote URLs if given
  console.log(chalk.cyan(__('appStatic')));
  tuiEvent('phase', { text: 'Static scan: collecting sources…' });
  if (afterSessions && remote.seeds.length > 0) console.log(chalk.gray(`--remote ${remote.hosts.join(', ')}: downloaded after each session, with the ${headerNames.join(', ')} the app sends there`));
  const fetched = await collectRemote({ remote: afterSessions ? [] : remote.seeds, guessed: remote.guessed, headers, scope, allowHosts: afterSessions || remote.seeds.length === 0 ? [] : remote.hosts, offline: options.offline });
  // the profile review and the password trace belong to the sessions, after the app has been used
  const staticResult = await step('static', { extraInputs: fetched.extraInputs, remoteDiagnostics: fetched.remoteDiagnostics, canaries: [], userData: undefined });
  if (options.campaignPlan) writeCampaignPlan(options.campaignPlan, staticResult.issues);

  // 2. watch sessions, until the user stops
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
    if (interactive && options.sessions === undefined && (isTuiWorker || !campaign && !options.debugUrl && !options.debugLaunch)) {
      tuiEvent('phase', { text: n === 1 ? 'Static results ready. Choose Start next session or Finish.' : `Session ${n - 1} results ready. Review before starting session ${n}.` });
      const answer = await ask(isTuiWorker ? (n === 1 ? 'Static scan complete. Start the first watch session, or finish and write the combined reports?' : `Session ${n - 1} complete. Review its results, then start session ${n} or finish and write the combined reports.`)
        : chalk.cyan(__(n === 1 ? 'appAskFirstSession' : 'appAskNextSession', { n })) + ' ', undefined, false, 'session');
      if (isTuiWorker ? answer !== 'start' : /^[snq]/.test(answer)) break;
    }
    let session;
    try {
      tuiEvent('session-start', { number: n });
      session = await observeSession({ watch: options.debugUrl ? located.folder : located.kind === 'project' ? located.folder : located.executable, args: watchArgs, ...debug, marker, active: !!(options.activeTests || campaign || options.autoCampaign), campaign, autoCampaign: !!options.autoCampaign, capture, traffic, scope,
        screenshots: screenshots && (path.isAbsolute(screenshots) ? screenshots : path.join(outDir, screenshots)),
        prove: !!options.prove, proofProfile: options.proofProfile ? loadProfile(options.proofProfile) : undefined,
        ipcProfile: options.ipcProfile ? loadProfile(options.ipcProfile, true) : undefined, logout: !!options.logoutCheck,
        reveal: common.reveal, canaries: common.canaries, searchDirs: common.searchDirs, userData: common.userData, assistant, confirm: interactiveConfirm(),
        remoteHosts: remote.hosts, headerNames });
    } catch (error) {
      console.error(chalk.red(error.message));
      process.exitCode = 1;
      break;
    }
    // headers go to the --remote sites (and without them the --scope domains) only, not to whatever the session captured;
    // with --remote, nothing outside its hosts is downloaded
    tuiEvent('phase', { text: `Session ${n}: collecting captured sources and writing its reports…` });
    const captured = await collectRemote({ runtime: session.runtime, watchLog: session.watchLog, capture, remote: afterSessions ? remote.seeds : [], guessed: remote.guessed, headers, headerSites: remote.seeds, scope,
      allowHosts: remote.hosts, headersByHost: session.copiedHeaders || {}, offline: options.offline });
    await step(`session-${n}`, { runtime: session.runtime, credentials: session.credentials, watchDiagnostics: session.watchDiagnostics, runtimeElectronVersion: session.watchDiagnostics.electron,
      extraInputs: captured.extraInputs, remoteDiagnostics: captured.remoteDiagnostics });
  }
  assistant.printSummary('Validation across all sessions');
  // the report of the whole run: the static scan and every session, each finding once, with what each session validated
  console.log(chalk.cyan(`Writing the report of the whole run (${results.length} step${results.length === 1 ? '' : 's'}) and checking the components workbook's links...`));
  tuiEvent('phase', { text: 'Writing combined reports and checking component links…' });
  const combined = await writeCombinedReport({ outDir, results, steps: stepNames, outputs: finalOutputs, shares: shareTypes.map(type => path.join(outDir, `shareable-report${type}`)),
    diagnostics: path.join(outDir, 'diagnostics.json'), stepDiagnostics, root: located.code, isRelative: common.isRelative, redact: common.redact,
    reveal: common.reveal, shareCode: common.shareCode, version: pkg.version });
  console.log(chalk.green(__('appStepDone', { file: finalOutputs.find(file => /\.html?$/i.test(file)) || finalOutputs[0], ...countBySeverity(combined.reported) })));
  console.log(chalk.green(__('appDone', { dir: outDir })));
  for (const file of combined.written) console.log(`  ${file}`);
  console.log(`  ${stepsDir} (each step's reports, kept as backups)`);
  publishFindings(combined, 'Combined');
  return combined;
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 2;
}).finally(() => {
  if (isTuiWorker && process.connected) process.disconnect();
});

function publishFindings(result, step = 'Scan') {
  if (!isTuiWorker) return;
  tuiEvent('findings', { counts: countBySeverity(result.reported), items: result.reported.slice(0, 500).map(issue => ({
    severity: issue.severity.name, id: issue.id, file: `[${step}] ${issue.file}`, line: issue.location?.line,
    description: issue.description.slice(0, 500),
  })) });
}

function writeCampaignPlan(file, issues) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const plan = campaignPlan(issues);
  fs.writeFileSync(file, JSON.stringify(plan, null, 2));
  console.log(`Campaign plan: ${file} (${plan.items.length} draft(s), workflow details required before execution)`);
}
