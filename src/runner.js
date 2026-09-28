import path from 'node:path';
import cliProgress from 'cli-progress';
import Table from 'cli-table3';
import chalk from 'chalk';
import logger from './util/logger.js';

import _i18n from './locales/i18n.js';
import { LoaderFile, LoaderAsar, LoaderDirectory, LoaderCombined } from './loader/index.js';
import { Parser } from './parser/index.js';
import { Finder } from './finder/index.js';
import { ProjectIndex } from './finder/project_index.js';
import { loadBaseline, applyBaseline, writeBaseline } from './util/baseline.js';
import { reconcileRuntime } from './watch/reconcile.js';
import { analyzePackagedFuses, packagedBinaryFor, readElectronVersion, fuseBinaryFor } from './watch/fuses.js';
import { GlobalChecks, severity, confidence } from './finder/index.js';
import { extension, input_exists, is_directory, writeIssues, getRelativePath, outputFormat } from './util/index.js';
import { dependencyReport, sortRows } from './util/dependencies.js';
import { validationHint } from './finder/consequences.js';
import { startDiagnostics, stopDiagnostics, diagnostics, writeDiagnostics } from './util/diagnostics.js';
import pkg from '../package.json' with { type: 'json' };
import { detectLibraries } from './util/libraries.js';
import { analyzeCaptures } from './traffic/ingest.js';
import { reconcileTraffic } from './traffic/reconcile.js';
import { reviewDataAtRest, appNames } from './storage/index.js';
import { secretSources, scanSecrets } from './secrets/scan.js';
import { linkCredentialStores } from './finder/checks/AtomicChecks/StorageChecks.js';

export default async function run(options, forCli = false) {
  // --offline only applies to this scan
  const previousOffline = process.env.ELECTRONEGATIVITY_OFFLINE;
  if (options.offline) process.env.ELECTRONEGATIVITY_OFFLINE = '1';
  if (options.diagnostics) startDiagnostics();
  try {
    return await scan(options, forCli);
  } finally {
    stopDiagnostics();
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

  let phaseStart = performance.now();
  const endPhase = (name) => {
    const collector = diagnostics();
    if (collector) collector.phase(name, performance.now() - phaseStart);
    phaseStart = performance.now();
  };
  // a packaged app's resources/app folder, or front-end code downloaded from a server: all of it ships (see isNonAppFile)
  const packagedInput = /[\\/]resources[\\/]app[\\/]?$/i.test(path.resolve(options.input)) ||
    (options.extraInputs || []).some(extra => extra && extra.dir && path.resolve(extra.dir) === path.resolve(options.input));
  await loader.load(options.input, { allFiles: !!options.allFiles, packaged: packagedInput });
  // front-end code captured from a server (--remote, or scripts pages loaded during --watch), scanned with the app.
  // Findings in it point at the URL the file was served from.
  const remoteLabels = new Map();
  const extraInputs = (options.extraInputs || []).filter(extra => extra && extra.dir && is_directory(extra.dir));
  if (extraInputs.length > 0) {
    const extras = [];
    for (const extra of extraInputs) {
      const extraLoader = new LoaderDirectory();
      await extraLoader.load(extra.dir, { allFiles: !!options.allFiles, packaged: true });
      extras.push(extraLoader);
      for (const [file, label] of extra.labels || []) remoteLabels.set(file, label);
    }
    loader = new LoaderCombined(loader, extras);
  }
  endPhase('load');
  // a packaged app's app.asar rarely names its Electron version: read it from the executable next to it, or use the
  // version watch mode saw the app run with
  let binaryVersion;
  if (!options.electronVersionOverride && !loader.electronVersion) {
    const binary = packagedBinaryFor(options.input);
    binaryVersion = binary ? readElectronVersion(fuseBinaryFor(binary)) : undefined;
  }
  const electronVersion = options.electronVersionOverride || loader.electronVersion || binaryVersion || options.runtimeElectronVersion;
  const electronVersionSource = options.electronVersionOverride ? 'override' : loader.electronVersion ? 'detected'
    : binaryVersion ? 'packaged executable' : options.runtimeElectronVersion ? 'observed at runtime' : 'not found (oldest defaults assumed)';
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
  // the hard-coded secret scan: -l HardcodedSecretsCheck to run it alone, -x HardcodedSecretsCheck to leave it out
  const SECRET_SCAN = ['hardcodedsecretscheck', 'hardcoded_secret'];
  const runSecretScan = (options.customScan.length === 0 || options.customScan.some(c => SECRET_SCAN.includes(c))) && !options.excludeFromScan.some(c => SECRET_SCAN.includes(c));

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

  const detectedLibraries = [];
  try {
    if (forCli) progress.start(filenames.length, 0);

    for (const file of filenames) {
      if (forCli) progress.increment();

      try {
        const buffer = loader.load_buffer(file);
        // libraries inside scripts and bundles (by their banners or version strings), for the dependency inventory
        if (/\.([cm]?js|html?)$/i.test(file) && buffer) {
          for (const library of detectLibraries(String(buffer))) detectedLibraries.push({ ...library, file });
        }
        const [type, data, content, warnings] = parser.parse(file, buffer);
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
    endPhase('checks');
    // checks that crashed on a file were isolated: report them with the files that couldn't be analyzed
    errors.push(...finder.checkErrors);

    // copies of libraries skipped by the scan still count for the dependency advisory checks
    if (finder._enabled_checks.some(check => check.name === 'DependencyInventoryLockCheck')) {
      // a packaged app has no lockfile: the packages in its node_modules stand in for it
      const lockfileInventory = issues.some(i => i.id === 'DEPENDENCY_INVENTORY_LOCK_CHECK');
      const installed = lockfileInventory ? [] : (loader.installedPackages || []);
      if (installed.length > 0) {
        issues.push({ file: 'node_modules', sample: '', location: { line: 1, column: 0 }, id: 'DEPENDENCY_INVENTORY_LOCK_CHECK',
          description: `${__('DEPENDENCY_INVENTORY_LOCK_CHECK')} (${installed.length} packages shipped in node_modules)`,
          properties: { packages: installed.map(({ name, version }) => ({ name, version, dev: false, line: 1, installed: true })) }, severity: severity.INFORMATIONAL,
          confidence: confidence.CERTAIN, manualReview: false, shortenedURL: 'https://osv.dev', visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false },
          constructorName: 'DependencyInventoryLockCheck' });
      }
      const listed = new Set();
      for (const { name, version, file } of [...(loader.vendoredLibraries || []), ...detectedLibraries]) {
        if (!version || listed.has(`${name}@${version}@${file}`)) continue;
        listed.add(`${name}@${version}@${file}`);
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
  // the global checks consume the package inventory: keep it for the dependency table
  const inventory = issues.filter(i => i.id === 'DEPENDENCY_INVENTORY_LOCK_CHECK');
  issues = await globalChecker.getResults(issues, options.output);
  endPhase('globalChecks');
  // hard-coded secrets in everything that ships: code, configuration files, native modules and helper binaries
  if (runSecretScan) {
    issues.push(...scanSecrets(secretSources(options.input, filenames, (file) => loader.load_buffer(file), { allFiles: !!options.allFiles })));
    endPhase('secrets');
  }
  linkCredentialStores(issues);
  errors.push(...globalChecker.checkErrors);
  if (forCli) for (const error of globalChecker.checkErrors) console.error(chalk.red(error.message));

  for (const issue of issues) if (remoteLabels.has(issue.file)) issue.file = remoteLabels.get(issue.file);

  // the dependency table of HTML and JSON reports (online lookups of release dates, support and advisories)
  let dependencies;
  if (options.dependencies ?? (options.output && ['html', 'json'].includes(outputFormat(options.output, options.isSarif)))) {
    for (const issue of inventory) if (remoteLabels.has(issue.file)) issue.file = remoteLabels.get(issue.file);
    dependencies = await dependencyTable(inventory, filenames, loader, electronVersion, options.input);
    endPhase('dependencies');
  }

  // Adjust visibility
  issues = issues.filter(i => !Object.hasOwn(i, 'visibility') || (!i.visibility.inlineDisabled && !i.visibility.globalCheckDisabled));

  // findings observed while the app ran (--watch), reconciled with the static findings (linked windows, coverage)
  if (options.runtime) {
    issues.push(...options.runtime.issues);
    reconcileRuntime(issues, options.runtime.summary);
  }
  // saved captures of the app's traffic (--ingest: HAR or Burp XML), checked by the same traffic checks as watch mode
  let traffic;
  if (options.captures && options.captures.length > 0) {
    traffic = analyzeCaptures(options.captures, { scope: options.scope || [] });
    issues.push(...traffic.issues);
    for (const message of traffic.summary.errors) errors.push({ file: 'capture', message, tolerable: false });
    if (forCli) console.log(chalk.green(__('trafficSummary', { files: traffic.summary.files, http: traffic.summary.http, ws: traffic.summary.ws, hosts: traffic.summary.hosts })));
  }
  if (traffic || (options.runtime && options.runtime.summary && options.runtime.summary.traffic))
    reconcileTraffic(issues, { interceptedHttps: traffic ? traffic.summary.interceptedHttps : 0 });

  // A packaged app (its app.asar or resources/app): read the fuses written into its executable, which are what ships.
  // Watch mode of a packaged app has already done so.
  if (readBinaryFuses && !issues.some(i => i.id === 'PACKAGED_FUSES')) {
    const binary = packagedBinaryFor(options.input);
    const fuses = binary ? analyzePackagedFuses(binary) : undefined;
    if (fuses && fuses.read) issues.push(...fuses.issues);
  }
  // the fuses in the binary are the ground truth: they replace the guess that no fuse configuration exists
  if (issues.some(i => i.id === 'PACKAGED_FUSES')) issues = issues.filter(i => i.id !== 'FUSES_GLOBAL_CHECK');

  // Data at rest: the app's profile (--user-data, and after a watch session) and where a remembered test password went
  // (--canary)
  let atRest;
  const reviewProfile = !!options.userData || !!options.runtime;
  if (reviewProfile || (options.canaries || []).length > 0) {
    const credentials = options.credentials || {};
    const names = credentials.names || appNames(topManifest(filenames, loader), options.appNames || []);
    const packagedApp = /[\\/]resources[\\/]app(\.asar)?$/i.test(path.resolve(options.input)) ? path.dirname(path.dirname(path.resolve(options.input))) : undefined;
    atRest = reviewDataAtRest({ names, userData: options.userData, observedUserData: options.runtime && options.runtime.summary && options.runtime.summary.userData,
      review: reviewProfile, canaries: options.canaries || [], searchDirs: options.searchDirs || [], installDir: credentials.installDir || packagedApp,
      baseline: credentials.baseline, cookieEncryption: cookieEncryptionFuse(issues), reveal: !!options.reveal });
    issues.push(...atRest.issues);
    for (const note of atRest.notes) errors.push({ file: 'data at rest', message: note, tolerable: true });
    if (forCli) for (const note of atRest.notes) console.log(chalk.yellow(note));
  }

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
      runtime: options.runtime && options.runtime.summary,
      traffic: traffic && traffic.summary,
      atRest: atRest && atRest.summary,
      dependencies
    });
  }

  if (forCli) {
    if (rows.length > 0) {
      table.push(...rows);
      console.log(table.toString());
    } else console.log(chalk.green(`\n${__('noIssuesFound')}`));
    if (suppressed.length > 0 || stale.length > 0) console.log(chalk.gray(__('baselineSummary', { suppressed: suppressed.length, stale: stale.length })));
    // what it takes to settle the findings that need review: most can be checked in a watch session with a marker
    const review = reported.filter(i => i.manualReview && !i.validation);
    const automatic = review.filter(i => /^(Automatic|Semi-automatic|Partly automatic)/.test(validationHint(i.id) || ''));
    if (review.length > 0 && !options.runtime)
      console.log(chalk.cyan(`${review.length} finding(s) need review; ${automatic.length} of them can be checked automatically in a watch session: electronegativity --app <install folder>, then follow its prompts. The report says how to check each one.`));
    console.log('\x1b[4m\x1b[36m%s\x1b[0m',`${__('tryElectroNg')}`);
  }
  if (options.diagnostics) {
    const byExtension = {};
    for (const file of filenames) {
      const ext = path.extname(file).toLowerCase() || path.basename(file);
      byExtension[ext] = (byExtension[ext] || 0) + 1;
    }
    writeDiagnostics(options.diagnostics, {
      input: options.input,
      inputType: is_directory(options.input) ? 'directory' : extension(options.input) === 'asar' ? 'asar' : 'file',
      electronVersion,
      electronVersionSource,
      files: { scanned: filenames.length, byExtension, skipped: loader.skipped, installedPackages: (loader.installedPackages || []).length, bundledLibraries: (loader.vendoredLibraries || []).map(l => `${l.name}@${l.version || '?'}`),
        // libraries recognized inside scripts and bundles by their banners or version strings (names are public packages)
        librariesInScripts: [...new Set(detectedLibraries.map(l => `${l.name}@${l.version}`))] },
      errors,
      issues: [...issues, ...suppressed],
      options: {
        output: options.output ? path.extname(options.output) : undefined, offline: !!options.offline, allFiles: !!options.allFiles,
        checks: options.customScan.length || 'all', excluded: options.excludeFromScan.length, electronVersionOverride: options.electronVersionOverride,
        baseline: !!options.baseline, severity: options.severitySet && options.severitySet.name, confidence: options.confidenceSet && options.confidenceSet.name,
        upgrade: options.electronUpgrade, watch: !!options.runtime,
      },
      dependencies: dependencies && { packages: dependencies.rows.length, withAdvisories: dependencies.rows.filter(r => r.advisories.length > 0).length,
        unsupported: dependencies.rows.filter(r => r.support.status === 'unsupported').length, offline: dependencies.offline,
        bundled: dependencies.rows.filter(r => r.kinds.includes('bundled library')).map(r => `${r.name}@${r.version}`).slice(0, 50),
        flagged: dependencies.rows.filter(r => r.advisories.length > 0 || r.support.status === 'unsupported')
          .map(r => `${r.name}@${r.version} (${r.support.status}, ${r.advisories.length} advisories)`).slice(0, 50),
        lookupErrors: dependencies.errors.map(e => `${e.source}: ${e.message}`).filter((m, i, all) => all.indexOf(m) === i).slice(0, 10) },
      watch: options.watchDiagnostics,
      remote: options.remoteDiagnostics,
      // how much traffic the captures held (hosts are left out: they identify the app)
      traffic: traffic && { files: traffic.summary.files, http: traffic.summary.http, ws: traffic.summary.ws, hosts: traffic.summary.hosts, errors: traffic.summary.errors.length },
    }, { redact: options.redact || [], version: pkg.version });
    if (forCli) console.log(chalk.gray(__('diagnosticsWritten', { file: options.diagnostics })));
  }

  return {
    electronVersion: electronVersion || null,
    electronVersionSource,
    globalChecks: globalChecker._enabled_checks.length,
    atomicChecks: finder._enabled_checks.length,
    errors,
    issues,
    reported,
    dependencies,
    suppressed,
    staleBaselineEntries: stale,
    traffic: traffic && traffic.summary,
    atRest: atRest && atRest.summary
  };
}

// The app's own package.json (the one closest to the top of the scanned code), or undefined
function topManifest(filenames, loader) {
  const manifest = filenames.filter(f => path.basename(f) === 'package.json' && !f.split(/[\\/]/).includes('node_modules'))
    .sort((a, b) => a.split(/[\\/]/).length - b.split(/[\\/]/).length)[0];
  try {
    return manifest ? JSON.parse(String(loader.load_buffer(manifest))) : undefined;
  } catch {
    return undefined;
  }
}

// the EnableCookieEncryption fuse read from the packaged binary: true, false, or undefined when unknown
function cookieEncryptionFuse(issues) {
  const fuses = issues.filter(i => i.id === 'PACKAGED_FUSES' && i.properties);
  if (fuses.some(i => i.properties.fuse === 'EnableCookieEncryption')) return false;
  const states = fuses.map(i => i.properties.states).find(Boolean);
  return states ? states.EnableCookieEncryption === 'enabled' : undefined;
}

// Every package and library found (lockfiles, node_modules, library copies and bundles), once per name and version,
// with the Electron runtime itself
async function dependencyTable(issues, filenames, loader, electronVersion, input) {
  let direct = {};
  const json = topManifest(filenames, loader) || {};
  direct = { ...Object.fromEntries(Object.keys(json.dependencies || {}).map(n => [n, 'dependency'])), ...Object.fromEntries(Object.keys(json.devDependencies || {}).map(n => [n, 'dev'])) };
  const byKey = new Map();
  const add = (name, version, kind, file, dev) => {
    const key = `${name}@${version}`;
    const row = byKey.get(key) || { name, version, kinds: [], files: [], dev: true, direct: Object.hasOwn(direct, name) };
    if (!row.kinds.includes(kind)) row.kinds.push(kind);
    if (file && !row.files.includes(file) && row.files.length < 5) row.files.push(file);
    row.dev = row.dev && !!dev;
    byKey.set(key, row);
  };
  if (electronVersion) add('electron', electronVersion, 'Electron runtime', undefined, false);
  for (const issue of issues) {
    if (issue.id !== 'DEPENDENCY_INVENTORY_LOCK_CHECK') continue;
    for (const pkg of (issue.properties && issue.properties.packages) || []) {
      if (!pkg.name || !pkg.version) continue;
      const kind = pkg.vendored ? 'bundled library' : pkg.installed ? 'node_modules' : 'lockfile';
      const file = pkg.vendored ? (path.isAbsolute(issue.file) ? getRelativePath(input, issue.file) : issue.file) : undefined;
      add(pkg.name, pkg.version, kind, file, pkg.dev || (pkg.name !== 'electron' && direct[pkg.name] === 'dev'));
    }
  }
  const report = await dependencyReport([...byKey.values()]);
  report.rows = sortRows(report.rows);
  return report;
}

// Lets CommonJS consumers keep using `const run = require('@doyensec/electronegativity')` (Node's require(esm))
export { run as 'module.exports' };
