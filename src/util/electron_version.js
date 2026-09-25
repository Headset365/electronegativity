import fs from 'node:fs';
import path from 'node:path';
import { compare, minVersion, valid } from 'semver';
import lockfile from '@yarnpkg/lockfile';
import { parse as parseYaml } from 'yaml';

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

export function findElectronVersionsFromPnpmLock(pnpmLockData) {
  const data = parseYaml(pnpmLockData.toString());
  const versions = [];

  // pnpm >= 7 keys look like "electron@30.0.0" (v9) or "/electron@30.0.0" (v6); older ones "/electron/30.0.0"
  for (const key of Object.keys(data.packages || {})) {
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
 *
 * @returns {string} The oldest version found.
 */
export async function findOldestElectronVersion(places) {
  let versions = [];

  const collect = (fn) => {
    try {
      const found = fn();
      if (Array.isArray(found)) versions.push(...found);
      else if (found) versions.push(found);
    } catch {
      // a malformed lockfile should not prevent the scan
    }
  };

  if (places.pjsonData) collect(() => findElectronVersionFromPackageJson(places.pjsonData));
  if (places.rootPath) versions.push(...await findElectronVersionsFromInstalledPackages(places.rootPath));
  if (places.plockData) collect(() => findElectronVersionsFromPackageLock(places.plockData));
  if (places.yarnLockData) collect(() => findElectronVersionsFromYarnLock(places.yarnLockData));
  if (places.pnpmLockData) collect(() => findElectronVersionsFromPnpmLock(places.pnpmLockData));

  return oldestVersion(versions);
}
