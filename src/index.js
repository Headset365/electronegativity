#!/usr/bin/env node

import path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import pkg from '../package.json' with { type: 'json' };
import _i18n from './locales/i18n.js';
import run from './runner.js';

async function main() {

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

  if(!options.input){
    program.outputHelp();
    process.exit(1);
  }

  if(options.output){
    options.fileFormat = options.output.split('.').pop();
    if(options.fileFormat !== 'csv' && options.fileFormat !== 'sarif'){
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

  try {
    await run({
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
      parserPlugins: options.parserPlugins
    }, forCli);
  } catch (error) {
    console.error(chalk.red(error.stack));
    process.exit(1);
  }
}

main();
