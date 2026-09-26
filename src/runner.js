import cliProgress from 'cli-progress';
import Table from 'cli-table3';
import chalk from 'chalk';
import logger from './util/logger.js';

import _i18n from './locales/i18n.js';
import { LoaderFile, LoaderAsar, LoaderDirectory } from './loader/index.js';
import { Parser } from './parser/index.js';
import { Finder } from './finder/index.js';
import { ProjectIndex } from './finder/project_index.js';
import { loadBaseline, applyBaseline, writeBaseline } from './util/baseline.js';
import { reconcileRuntime } from './watch/reconcile.js';
import { analyzePackagedFuses, packagedBinaryFor } from './watch/fuses.js';
import { GlobalChecks, severity, confidence } from './finder/index.js';
import { extension, input_exists, is_directory, writeIssues, getRelativePath } from './util/index.js';

export default async function run(options, forCli = false) {
  // --offline only applies to this scan
  const previousOffline = process.env.ELECTRONEGATIVITY_OFFLINE;
  if (options.offline) process.env.ELECTRONEGATIVITY_OFFLINE = '1';
  try {
    return await scan(options, forCli);
  } finally {
    if (previousOffline === undefined) delete process.env.ELECTRONEGATIVITY_OFFLINE;
    else process.env.ELECTRONEGATIVITY_OFFLINE = previousOffline;
  }
}

async function scan(options, forCli) {
  await _i18n(); // wait for the _i18n function to complete

  if (!input_exists(options.input)) {
    const err = 'Input does not exist!';
    if (forCli) {
      console.error(chalk.red(err));
      process.exit(1);
    }
    else throw new Error(err);
  }

  // Load
  let loader;

  if(is_directory(options.input)){
    loader = new LoaderDirectory();
  }else{
    loader = (extension(options.input) === 'asar') ? new LoaderAsar() : new LoaderFile();
  }

  await loader.load(options.input, { allFiles: !!options.allFiles });
  const electronVersion = options.electronVersionOverride || loader.electronVersion;
  if (!electronVersion)
    logger.warn(__('electronVersionError'));

  if (options.severitySet) {
    if (!Object.hasOwn(severity, options.severitySet.toUpperCase())) {
      const err = __('severityLevelError');
      if (forCli) {
        console.error(chalk.red(err));
        process.exit(1);
      } else throw new Error(err);
    } else options.severitySet = severity[options.severitySet.toUpperCase()];
  } else options.severitySet = severity["INFORMATIONAL"]; // default to lowest

  if (options.confidenceSet) {
    if (!Object.hasOwn(confidence, options.confidenceSet.toUpperCase())) {
      const err = __('confidenceLevelError');
      if (forCli) {
        console.error(chalk.red(err));
        process.exit(1);
      } else throw new Error(err);
    } else options.confidenceSet = confidence[options.confidenceSet.toUpperCase()];
  } else options.confidenceSet = confidence["TENTATIVE"]; // default to lowest

  // Normalize the user-provided list. They should be already normalized if coming from the index.js,
  // but this is not granted in case Electronegativity is used programmatically
  options.customScan = (options.customScan || []).map(c => c.toLowerCase());
  // read the fuses of a packaged binary unless the fuse checks were left out (-l without them, or -x)
  const readBinaryFuses = (options.customScan.length === 0 || options.customScan.includes('fusesglobalcheck')) &&
    !(options.excludeFromScan || []).map(c => c.toLowerCase()).includes('fusesglobalcheck');
  options.excludeFromScan = (options.excludeFromScan || []).map(c => c.toLowerCase());

  // Parser options initialization
  const parser = new Parser(false, true);

  if (options.parserPlugins && Array.isArray(options.parserPlugins) && options.parserPlugins.length > 0) {
    options.parserPlugins.forEach(plugin => parser.addPlugin(plugin));
  }

  // Global Checker initialization
  const globalChecker = new GlobalChecks(options.customScan, options.excludeFromScan, options.electronUpgrade);

  // Custom/Exclusion Scans initialization
  if (options.customScan.length > 0) options.customScan = options.customScan.filter(r => !r.includes('globalcheck')).concat(globalChecker.dependencies);
  if (options.excludeFromScan.length > 0) options.excludeFromScan = options.excludeFromScan.filter(r => !r.includes('globalcheck'));

  // Finder initialization
  const finder = await new Finder(options.customScan, options.excludeFromScan, options.electronUpgrade);
  // lets checks follow handlers and constants imported from other files
  finder.projectIndex = new ProjectIndex(loader, new Parser(false, true), is_directory(options.input) ? options.input : undefined);
  const filenames = [...loader.list_files];

  // Results' table initialization
  let issues = [];
  let errors = [];
  let table = new Table({
    head: [__('tableCheckId'), __('tableAffectedFile'), __('tableLocation'), __('tableDescription')],
    colWidths:[undefined, undefined, undefined, 50], // necessary for wordWrap
    wordWrap: true
  });

  if (forCli) console.log(chalk.green(`${__('numberOfChecksLoaded', {total: globalChecker._enabled_checks.length+finder._enabled_checks.length, globalChecks: globalChecker._enabled_checks.length, atomicChecks: finder._enabled_checks.length})}`));

  let progress;
  let oldLog;
  let consoleArguments = [];
  if (forCli) {
    progress = new cliProgress.SingleBar({format: '{bar} {percentage}% | {value}/{total}'}, cliProgress.Presets.shades_grey);
    oldLog = console.log;
    console.log = function () {
      consoleArguments.push(arguments);
    };
  }

  try {
    if (forCli) progress.start(filenames.length, 0);

    for (const file of filenames) {
      if (forCli) progress.increment();

      try {
        const [type, data, content, warnings] = parser.parse(file, loader.load_buffer(file));
        if (data === null)
          continue;

        if (warnings !== undefined) {
          for (const warning of warnings) {
            errors.push({ file: file, message: warning.message, tolerable: true });
          }
        }

        const result = await finder.find(file, data, type, content, null, electronVersion);
        issues.push(...result);
      } catch (error) {
        errors.push({ file: file, message: error.message, tolerable: false });
      }
    }

    if (forCli) progress.stop();

    // copies of libraries skipped by the scan still count for the dependency advisory checks
    if (finder._enabled_checks.some(check => check.name === 'DependencyInventoryLockCheck')) {
      for (const { name, version, file } of loader.vendoredLibraries || []) {
        if (!version) continue;
        issues.push({ file, sample: '', location: { line: 1, column: 0 }, id: 'DEPENDENCY_INVENTORY_LOCK_CHECK', description: `${__('DEPENDENCY_INVENTORY_LOCK_CHECK')} (${name}@${version})`,
          properties: { packages: [{ name, version, dev: false, line: 1, vendored: true }] }, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN,
          manualReview: false, shortenedURL: 'https://osv.dev', visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false },
          constructorName: 'DependencyInventoryLockCheck' });
      }
    }
  }
  finally {
    if (forCli) {
      console.log = oldLog;
      for (let i = 0; i < consoleArguments.length; i++)
        console.log.apply(this, consoleArguments[i]);
    }
  }

  if (forCli) {
    for (const error of errors) {
      if (error.tolerable) console.log(chalk.yellow(`${__('tolerableErrorParsing', {file: error.file, message: error.message})}`));
      else console.error(chalk.red(`${__('errorParsing', {file: error.file, message: error.message})}`));
    }
  }

  // Second pass of checks (in "GlobalChecks")
  // Now that we have all the "naive" findings we may analyze them further to sort out false negatives
  // and false positives before presenting them in the final report (e.g. CSP)
  issues = await globalChecker.getResults(issues, options.output);

  // Adjust visibility
  issues = issues.filter(i => !Object.hasOwn(i, 'visibility') || (!i.visibility.inlineDisabled && !i.visibility.globalCheckDisabled));

  // findings observed while the app ran (--watch), reconciled with the static findings (linked windows, coverage)
  if (options.runtime) {
    issues.push(...options.runtime.issues);
    reconcileRuntime(issues);
  }

  // A packaged app (its app.asar or resources/app): read the fuses written into its executable, which are what ships.
  // Watch mode of a packaged app has already done so.
  if (readBinaryFuses && !issues.some(i => i.id === 'PACKAGED_FUSES')) {
    const binary = packagedBinaryFor(options.input);
    const fuses = binary ? analyzePackagedFuses(binary) : undefined;
    if (fuses && fuses.read) issues.push(...fuses.issues);
  }
  // the fuses in the binary are the ground truth: they replace the guess that no fuse configuration exists
  if (issues.some(i => i.id === 'PACKAGED_FUSES')) issues = issues.filter(i => i.id !== 'FUSES_GLOBAL_CHECK');

  // Baseline: accepted findings are not reported again
  let suppressed = [];
  let stale = [];
  let previousBaseline;
  if (options.baseline && input_exists(options.baseline)) {
    previousBaseline = loadBaseline(options.baseline);
    ({ kept: issues, suppressed, stale } = applyBaseline(issues, previousBaseline, options.input));
  }
  if (options.writeBaseline) {
    const all = [...issues, ...suppressed];
    const count = writeBaseline(options.writeBaseline, all, options.input, previousBaseline || (input_exists(options.writeBaseline) ? loadBaseline(options.writeBaseline) : undefined));
    if (forCli) console.log(chalk.green(__('baselineWritten', { count, file: options.writeBaseline })));
  }

  // adjust to Relative or Absolute path
  if (options.isRelative)
    issues.forEach(function(issue, i, issues) {
      if (issue.constructorName !== 'Runtime') issues[i].file = getRelativePath(options.input, issue.file);
    });

  let rows = [];
  if (forCli) {
    for (const issue of issues) {
      if (
        issue.severity.value >= options.severitySet.value &&
        issue.confidence.value >= options.confidenceSet.value
      )
        rows.push([
          `${issue.id}${
            issue.manualReview ? chalk.bgRed(`\n*${__('reviewRequired')}*`) : ``
          }\n${issue.severity.format()} | ${issue.confidence.format()}`,
          issue.file,
          `${issue.location.line}:${issue.location.column}`,
          `${options.isVerbose ? issue.description + '\n' + issue.shortenedURL : issue.shortenedURL}`,
        ]);
    }
  }

  // file outputs and --fail-on honor the same severity/confidence thresholds as the CLI table
  const reported = issues.filter(issue => issue.severity.value >= options.severitySet.value && issue.confidence.value >= options.confidenceSet.value);

  if (options.output) {
    writeIssues(options.input, options.isRelative, options.output, reported, options.isSarif, {
      suppressedByBaseline: suppressed.length,
      electronVersion: electronVersion || null,
      filesScanned: filenames.length,
      globalChecks: globalChecker._enabled_checks.length,
      atomicChecks: finder._enabled_checks.length,
      errors,
      runtime: options.runtime && options.runtime.summary
    });
  }

  if (forCli) {
    if (rows.length > 0) {
      table.push(...rows);
      console.log(table.toString());
    } else console.log(chalk.green(`\n${__('noIssuesFound')}`));
    if (suppressed.length > 0 || stale.length > 0) console.log(chalk.gray(__('baselineSummary', { suppressed: suppressed.length, stale: stale.length })));
    console.log('\x1b[4m\x1b[36m%s\x1b[0m',`${__('tryElectroNg')}`);
  }
  return {
    globalChecks: globalChecker._enabled_checks.length,
    atomicChecks: finder._enabled_checks.length,
    errors,
    issues,
    reported,
    suppressed,
    staleBaselineEntries: stale
  };
}

// Lets CommonJS consumers keep using `const run = require('@doyensec/electronegativity')` (Node's require(esm))
export { run as 'module.exports' };
