#!/usr/bin/env node

import path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import pkg from '../package.json' with { type: 'json' };
import _i18n from './locales/i18n.js';
import run from './runner.js';
import { severity } from './finder/attributes.js';
import { OUTPUT_FORMATS } from './util/index.js';
import { resolveApp, watchApp } from './watch/launch.js';
import { readWatchLog, analyzeWatchLog } from './watch/analyze.js';
import { analyzePackagedFuses } from './watch/fuses.js';

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

  // Watch mode: run the app with the observation hook while the user goes through it, then analyze what happened
  let runtime;
  let watchDiagnostics;
  if (options.watch || options.watchLog) {
    let log = options.watchLog;
    let packagedApp;
    try {
      if (options.watch) {
        const app = resolveApp(options.watch);
        packagedApp = app.packaged ? app.command : undefined;
        if (!options.input && app.staticInput) options.input = app.staticInput;
        console.log(chalk.cyan(__('watchStarting')));
        log = await watchApp(options.watch, { args: options.watchArgs ? options.watchArgs.split(/\s+/).filter(Boolean) : [], marker: options.watchMarker });
        console.log(chalk.gray(__('watchLogSaved', { file: log })));
      }
      const records = readWatchLog(log);
      runtime = analyzeWatchLog(records);
      // for --diagnostics: what the hook captured, by kind, and anything that went wrong inside it
      const recordKinds = {};
      for (const record of records) recordKinds[record.kind] = (recordKinds[record.kind] || 0) + 1;
      const start = records.find(r => r.kind === 'start');
      watchDiagnostics = {
        mode: options.watch ? 'launched' : 'log', packaged: !!packagedApp, hookStarted: !!start, lateStart: !!(start && start.late),
        electron: start && start.electron, marker: !!options.watchMarker, records: recordKinds,
        hookErrors: records.filter(r => r.kind === 'hook-error').slice(0, 20).map(r => r.message), summary: { ...runtime.summary, fuses: undefined },
      };
      // read the fuses actually written into the packaged binary, which the static FUSES_* checks can't see
      if (packagedApp) {
        const fuses = analyzePackagedFuses(packagedApp);
        if (fuses.read) {
          runtime.issues.push(...fuses.issues);
          runtime.summary.fuses = fuses.states;
        } else console.error(chalk.yellow(__('watchFusesUnreadable', { file: fuses.binary })));
        watchDiagnostics.fusesRead = fuses.read;
      }
    } catch (error) {
      console.error(chalk.red(error.message));
      process.exit(2);
    }
    if (!runtime.summary.started) console.error(chalk.yellow(__('watchNoHook')));
  }

  if(!options.input){
    program.outputHelp();
    process.exit(1);
  }

  if(options.output){
    options.fileFormat = options.output.split('.').pop().toLowerCase();
    if(!OUTPUT_FORMATS.includes(options.fileFormat)){
      console.error(chalk.red(__('fileFormatError')));
      program.outputHelp();
      process.exit(1);
    }
  }

  if (typeof options.checks !== 'undefined' && options.checks){
    options.checks = options.checks.split(",").map(check => check.trim().toLowerCase());
  } else options.checks = [];

  if (typeof options.excludeChecks !== 'undefined' && options.excludeChecks){
    options.excludeChecks = options.excludeChecks.split(",").map(check => check.trim().toLowerCase());
  } else options.excludeChecks = [];

  if (typeof options.verbose !== 'undefined' && (falsyStrings.includes(options.verbose)))
    options.verbose = false;
  else
    options.verbose = true;

  if (typeof options.parserPlugins !== 'undefined' && options.parserPlugins)
    options.parserPlugins = options.parserPlugins.split(",").map(p => p.trim());
  else
    options.parserPlugins = [];


  const input = path.resolve(options.input);

  let failOn;
  if (options.failOn) {
    failOn = severity[options.failOn.toUpperCase()];
    if (!failOn) {
      console.error(chalk.red(__('severityLevelError')));
      process.exit(2);
    }
  }

  try {
    const result = await run({
      input,
      output: options.output,
      isSarif: options.fileFormat === 'sarif',
      customScan: options.checks,
      excludeFromScan: options.excludeChecks,
      severitySet: options.severity,
      confidenceSet: options.confidence,
      isRelative: options.relative,
      isVerbose: options.verbose,
      electronUpgrade: options.upgrade,
      electronVersionOverride: options.electronVersion,
      parserPlugins: options.parserPlugins,
      offline: options.offline,
      allFiles: options.allFiles,
      baseline: options.baseline,
      writeBaseline: options.writeBaseline,
      runtime,
      diagnostics: options.diagnostics,
      redact: options.redact ? options.redact.split(',').map(term => term.trim()).filter(Boolean) : [],
      watchDiagnostics
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

main();
