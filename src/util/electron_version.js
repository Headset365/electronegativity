import fs from 'node:fs';
import path from 'node:path';
import { compare, minVersion, valid } from 'semver';
import lockfile from '@yarnpkg/lockfile';
import { parse as parseYaml } from 'yaml';
import { pnpmLockPackages } from './lockfiles.js';
import { parseAllDocuments } from 'yaml';

export function minMatchingVersion(versionString) {
  try {
    const v = minVersion(versionString);
    return v.raw;
  } catch {
    return undefined;
  }
}

// As we cannot know which of potentially multiple Electron versions is actually in use, we always assume the oldest one just in case.
export function oldestVersion(versions) {
  const sortedVersions = (versions || []).filter(v => valid(v)).sort((a, b) => compare(a, b));
  return sortedVersions.length > 0 ? minMatchingVersion(sortedVersions[0]) : undefined;
}

export function findElectronVersionFromPackageJson(pjsonData) {
  const dependencies = Object.assign({}, pjsonData.devDependencies, pjsonData.dependencies);
  return minMatchingVersion(dependencies.electron);
}

export async function findElectronVersionsFromInstalledPackages(rootPath) {
  try {
    const pjson = JSON.parse(await fs.promises.readFile(path.join(rootPath, 'node_modules', 'electron', 'package.json'), 'utf8'));
    return [minMatchingVersion(pjson.version)].filter(Boolean);
  } catch {
    return [];
  }
}

export function findElectronVersionsFromPackageLock(plockData) {
  const versions = [];

  // lockfileVersion 2 and 3 (npm >= 7)
  if (plockData.packages) {
    for (const [location, pkg] of Object.entries(plockData.packages)) {
      if (location === 'node_modules/electron' || location.endsWith('/node_modules/electron'))
        versions.push(minMatchingVersion(pkg.version));
    }
  }

  // lockfileVersion 1 (npm <= 6), also the format produced by the Yarn classic lockfile parser
  if (versions.length === 0 && plockData.dependencies) {
    versions.push(...Object.entries(plockData.dependencies).filter(d => d[0] === 'electron' || d[0].startsWith('electron@')).map(d => minMatchingVersion(d[1].version)));
  }

  return versions.filter(Boolean);
}

export function findElectronVersionsFromYarnLock(yarnLockData) {
  yarnLockData = yarnLockData.toString();

  // Yarn Berry (v2+) lockfiles are YAML
  if (/^__metadata:/m.test(yarnLockData)) {
    const data = parseYaml(yarnLockData);
    return Object.entries(data)
      .filter(([descriptor]) => descriptor.split(/,\s*/).some(d => d.replace(/^"|"$/g, '').startsWith('electron@')))
      .map(([, entry]) => minMatchingVersion(entry.version))
      .filter(Boolean);
  }

  // Yarn classic (v1)
  const parsed = lockfile.parse(yarnLockData);
  if (parsed.type !== 'success') return [];
  return findElectronVersionsFromPackageLock({ dependencies: parsed.object });
}

// node-gyp style .npmrc used by apps building native modules against Electron: runtime="electron", target="43.7.3"
export function findElectronVersionFromNpmrc(npmrcData) {
  const settings = {};
  for (const line of npmrcData.toString().split(/\r?\n/)) {
    const match = line.match(/^\s*([\w-]+)\s*=\s*"?([^"#;]*)"?/);
    if (match) settings[match[1].toLowerCase()] = match[2].trim();
  }
  const isElectron = settings.runtime === 'electron' || /electronjs\.org|electron/i.test(settings.disturl || '');
  return isElectron ? minMatchingVersion(settings.target) : undefined;
}

export function findElectronVersionsFromPnpmLock(pnpmLockData) {
  const versions = [];

  // pnpm >= 7 keys look like "electron@30.0.0" (v9) or "/electron@30.0.0" (v6); older ones "/electron/30.0.0"
  for (const key of Object.keys(pnpmLockPackages(pnpmLockData.toString()))) {
    const match = key.match(/^\/?electron[@/](\d[^(@/]*)/);
    if (match) versions.push(minMatchingVersion(match[1]));
  }

  return versions.filter(Boolean);
}

/**
 * Returns the oldest Electron version found in the given places.
 *
 * @param {Object} places The places to scan for Electron versions, may contain the following options:
 * @param {Object} [places.pjsonData] The data from the package.json file.
 * @param {string} [places.rootPath] The path to the module (will then scan the installed packages).
 * @param {Object} [places.plockData] The data from the package-lock.json (or npm-shrinkwrap.json) file.
 * @param {string} [places.yarnLockData] The data from the yarn.lock file.
 * @param {string} [places.pnpmLockData] The data from the pnpm-lock.yaml file.
 * @param {string} [places.npmrcData] The data from the .npmrc file.
 *
 * @returns {string} The oldest version found.
 */
export async function findOldestElectronVersion(places) {
  const collect = (fn) => {
    try {
      const found = fn();
      return (Array.isArray(found) ? found : [found]).filter(Boolean);
    } catch {
      return []; // a malformed lockfile should not prevent the scan
    }
  };

  // What the app itself runs on: the installed package, the lockfile entries resolving the root package.json's
  // dependency, or the version node-gyp builds against. Lockfiles also list Electron copies pulled in by tools
  // (test runners, rebuild helpers...), so those are only used when nothing better is known.
  const root = [
    ...(places.rootPath ? await findElectronVersionsFromInstalledPackages(places.rootPath) : []),
    ...(places.plockData ? collect(() => findRootElectronFromPackageLock(places.plockData)) : []),
    ...(places.pnpmLockData ? collect(() => findRootElectronFromPnpmLock(places.pnpmLockData)) : []),
    ...(places.yarnLockData && places.pjsonData ? collect(() => findRootElectronFromYarnLock(places.yarnLockData, places.pjsonData)) : []),
    ...(places.npmrcData ? collect(() => findElectronVersionFromNpmrc(places.npmrcData)) : []),
  ];
  if (root.length > 0) return oldestVersion(root);

  const declared = places.pjsonData ? collect(() => findElectronVersionFromPackageJson(places.pjsonData)) : [];
  if (declared.length > 0) return oldestVersion(declared);

  return oldestVersion([
    ...(places.plockData ? collect(() => findElectronVersionsFromPackageLock(places.plockData)) : []),
    ...(places.yarnLockData ? collect(() => findElectronVersionsFromYarnLock(places.yarnLockData)) : []),
    ...(places.pnpmLockData ? collect(() => findElectronVersionsFromPnpmLock(places.pnpmLockData)) : []),
  ]);
}

// package-lock v2/v3: the top-level node_modules/electron is the root project's
export function findRootElectronFromPackageLock(plockData) {
  const pkg = plockData.packages && plockData.packages['node_modules/electron'];
  if (pkg) return [minMatchingVersion(pkg.version)];
  const dep = plockData.dependencies && plockData.dependencies.electron;
  return dep ? [minMatchingVersion(dep.version)] : [];
}

// pnpm: importers['.'] lists the root project's resolved dependencies
export function findRootElectronFromPnpmLock(pnpmLockData) {
  const versions = [];
  for (const doc of parseAllDocuments(pnpmLockData.toString())) {
    const data = doc.toJSON() || {};
    const root = data.importers && data.importers['.'];
    // lockfile v5 kept the root project's dependencies at the top level
    const sources = root ? [root] : [data];
    for (const source of sources) {
      for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        const entry = source[kind] && source[kind].electron;
        if (!entry) continue;
        const version = String(typeof entry === 'object' ? entry.version : entry).replace(/\(.*$/, '');
        versions.push(minMatchingVersion(version));
      }
    }
  }
  return versions;
}

// yarn: the entry whose descriptor matches the range of the root package.json
export function findRootElectronFromYarnLock(yarnLockData, pjsonData) {
  const range = Object.assign({}, pjsonData.devDependencies, pjsonData.dependencies).electron;
  if (!range) return [];
  const text = yarnLockData.toString();
  const descriptors = [`electron@${range}`, `electron@npm:${range}`];
  if (/^__metadata:/m.test(text)) {
    return Object.entries(parseYaml(text))
      .filter(([descriptor]) => descriptor.split(/,\s*/).some(d => descriptors.includes(d.replace(/^"|"$/g, ''))))
      .map(([, entry]) => minMatchingVersion(entry.version));
  }
  const parsed = lockfile.parse(text);
  if (parsed.type !== 'success') return [];
  const entry = parsed.object[`electron@${range}`];
  return entry ? [minMatchingVersion(entry.version)] : [];
}
