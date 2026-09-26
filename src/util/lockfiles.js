import path from 'node:path';
import lockfile from '@yarnpkg/lockfile';
import { parse as parseYaml, parseAllDocuments } from 'yaml';
import { valid } from 'semver';

export const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

export function isLockfile(filename) {
  return LOCKFILE_NAMES.includes(path.basename(filename).toLowerCase());
}

// "@scope/name@1.2.3" -> ["@scope/name", "1.2.3"]
function splitNameVersion(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return [spec, undefined];
  return [spec.slice(0, at), spec.slice(at + 1)];
}

function npmPackages(json) {
  const packages = [];
  if (json.packages) { // lockfileVersion 2 and 3
    for (const [location, pkg] of Object.entries(json.packages)) {
      if (!location || pkg.link || !pkg.version) continue;
      const name = pkg.name || location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
      packages.push({ name, version: pkg.version, dev: !!(pkg.dev || pkg.devOptional) });
    }
  } else if (json.dependencies) { // lockfileVersion 1
    const walk = (deps) => {
      for (const [name, pkg] of Object.entries(deps || {})) {
        if (pkg.version) packages.push({ name, version: pkg.version, dev: !!pkg.dev });
        walk(pkg.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return packages;
}

function yarnPackages(text) {
  const packages = [];
  if (/^__metadata:/m.test(text)) { // Yarn Berry
    for (const [descriptor, entry] of Object.entries(parseYaml(text) || {})) {
      if (descriptor === '__metadata' || !entry || !entry.resolution) continue;
      const [name, reference] = splitNameVersion(entry.resolution);
      if (!reference || !reference.startsWith('npm:')) continue; // workspaces, patches, git dependencies
      packages.push({ name, version: entry.version });
    }
    return packages;
  }
  const parsed = lockfile.parse(text); // Yarn classic
  if (parsed.type !== 'success') return packages;
  for (const [descriptor, entry] of Object.entries(parsed.object)) {
    const [name] = splitNameVersion(descriptor.split(/,\s*/)[0].replace(/^"|"$/g, ''));
    packages.push({ name, version: entry.version });
  }
  return packages;
}

// pnpm 9+ may write several YAML documents to one lockfile (e.g. for config dependencies), merge their packages
export function pnpmLockPackages(text) {
  const packages = {};
  for (const doc of parseAllDocuments(text)) {
    const data = doc.toJSON() || {};
    Object.assign(packages, data.packages || {});
  }
  return packages;
}

function pnpmPackages(text) {
  const packages = [];
  for (const [key, entry] of Object.entries(pnpmLockPackages(text))) {
    const spec = key.replace(/^\//, '').replace(/\(.*$/, ''); // "/name@1.0.0(peer@2)" -> "name@1.0.0"
    let [name, version] = splitNameVersion(spec);
    if (!version || !valid(version)) { // pnpm <= 5: "/name/1.0.0"
      const slash = spec.lastIndexOf('/');
      [name, version] = [spec.slice(0, slash), spec.slice(slash + 1)];
    }
    if (name && valid(version)) packages.push({ name, version, dev: entry && entry.dev === true });
  }
  return packages;
}

/**
 * Lists the packages installed according to a lockfile, as [{ name, version, dev, line }], deduplicated by name@version.
 * `dev` is only known for npm and old pnpm lockfiles.
 */
export function listLockfilePackages(filename, text) {
  const base = path.basename(filename).toLowerCase();
  let packages = [];
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') packages = npmPackages(JSON.parse(text));
  else if (base === 'yarn.lock') packages = yarnPackages(text);
  else if (base === 'pnpm-lock.yaml') packages = pnpmPackages(text);

  const lines = text.split('\n');
  const unique = new Map();
  for (const pkg of packages) {
    if (!pkg.name || !valid(pkg.version)) continue;
    const key = `${pkg.name}@${pkg.version}`;
    if (unique.has(key)) {
      // a package counts as a runtime dependency if any copy of it is
      if (!pkg.dev) unique.get(key).dev = false;
      continue;
    }
    const index = lines.findIndex(l => l.includes(`node_modules/${pkg.name}"`) || l.includes(`${pkg.name}@`));
    unique.set(key, { ...pkg, line: index + 1 || 1 });
  }
  return [...unique.values()];
}
