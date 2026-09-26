import fs from 'node:fs';
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

// Yarn lockfiles don't say which packages are dev-only: packages also carry what they depend on, see runtimePackages
function yarnPackages(text) {
  const packages = [];
  if (/^__metadata:/m.test(text)) { // Yarn Berry
    for (const [descriptor, entry] of Object.entries(parseYaml(text) || {})) {
      if (descriptor === '__metadata' || !entry || !entry.resolution) continue;
      const [name, reference] = splitNameVersion(entry.resolution);
      const descriptors = descriptor.split(/,\s*/);
      if (!reference || !reference.startsWith('npm:')) { // workspaces, patches, git dependencies
        packages.push({ name, descriptors, dependencies: entry.dependencies, local: true });
        continue;
      }
      packages.push({ name, version: entry.version, descriptors, dependencies: entry.dependencies });
    }
    return packages;
  }
  const parsed = lockfile.parse(text); // Yarn classic
  if (parsed.type !== 'success') return packages;
  for (const [descriptor, entry] of Object.entries(parsed.object)) {
    const [name] = splitNameVersion(descriptor.split(/,\s*/)[0].replace(/^"|"$/g, ''));
    packages.push({ name, version: entry.version, descriptors: [descriptor], dependencies: { ...entry.dependencies, ...entry.optionalDependencies } });
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

// pnpm 6+: dependencies of each package are in `packages` (up to v8) or `snapshots` (v9), roots in `importers`
function pnpmPackages(text) {
  const packages = [];
  const snapshots = {};
  const importers = {};
  for (const doc of parseAllDocuments(text)) {
    const data = doc.toJSON() || {};
    Object.assign(snapshots, data.packages || {}, data.snapshots || {});
    Object.assign(importers, data.importers || {});
  }
  const byId = new Map(); // v9 lists a package in `packages` and each of its peer variants in `snapshots`
  for (const [key, entry] of Object.entries(snapshots)) {
    const [name, version] = pnpmKey(key);
    if (!name || !valid(version)) continue;
    const id = `${name}@${version}`;
    const dependencies = { ...(entry && entry.dependencies), ...(entry && entry.optionalDependencies) };
    const existing = byId.get(id);
    if (existing) {
      Object.assign(existing.dependencies, dependencies);
      if (entry && entry.dev === false) existing.dev = false;
      continue;
    }
    const pkg = { name, version, dev: entry && typeof entry.dev === 'boolean' ? entry.dev : undefined, dependencies };
    byId.set(id, pkg);
    packages.push(pkg);
  }
  packages.importers = importers;
  return packages;
}

// "/name@1.0.0(peer@2)", "name@1.0.0", "/name/1.0.0" (pnpm <= 5) -> ["name", "1.0.0"]
function pnpmKey(key) {
  const spec = key.replace(/^\//, '').replace(/\(.*$/, '');
  let [name, version] = splitNameVersion(spec);
  if (!version || !valid(version)) {
    const slash = spec.lastIndexOf('/');
    [name, version] = [spec.slice(0, slash), spec.slice(slash + 1)];
  }
  return [name, version];
}

// The package.json files of a project and its workspaces (npm/yarn "workspaces", pnpm-workspace.yaml)
function manifests(directory) {
  const read = (file) => {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      return undefined;
    }
  };
  const root = read(path.join(directory, 'package.json'));
  if (!root) return [];
  let patterns = Array.isArray(root.workspaces) ? root.workspaces : (root.workspaces && root.workspaces.packages) || [];
  try {
    patterns = patterns.concat(parseYaml(fs.readFileSync(path.join(directory, 'pnpm-workspace.yaml'), 'utf8')).packages || []);
  } catch {
    // not a pnpm workspace
  }
  const found = [root];
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || pattern.startsWith('!')) continue;
    // "packages/*", "packages/**", "apps/desktop"
    const base = pattern.replace(/\/\*\*?$/, '');
    const dirs = base === pattern ? [path.join(directory, base)] : (() => {
      try {
        return fs.readdirSync(path.join(directory, base), { withFileTypes: true }).filter(e => e.isDirectory()).map(e => path.join(directory, base, e.name));
      } catch {
        return [];
      }
    })();
    for (const dir of dirs) {
      const manifest = read(path.join(dir, 'package.json'));
      if (manifest) found.push(manifest);
    }
  }
  return found;
}

/**
 * Marks the packages that the app doesn't need at runtime as dev, for lockfiles that don't record it (Yarn, pnpm 9):
 * packages reachable from the `dependencies` and `optionalDependencies` of the project's package.json files (and of
 * its workspaces) are runtime packages, everything else is only used for development.
 */
function markDevPackages(packages, directory) {
  if (packages.every(p => p.dev !== undefined || p.local)) return;
  const byName = new Map();
  const byDescriptor = new Map();
  for (const pkg of packages) {
    if (!byName.has(pkg.name)) byName.set(pkg.name, []);
    byName.get(pkg.name).push(pkg);
    for (const descriptor of pkg.descriptors || []) byDescriptor.set(descriptor.replace(/^"|"$/g, ''), pkg);
  }
  // name + range (yarn), or name + resolved version (pnpm) -> the packages it can resolve to
  const resolve = (name, range) => {
    const version = String(range || '').replace(/\(.*$/, '');
    const exact = byDescriptor.get(`${name}@${range}`) || byDescriptor.get(`${name}@npm:${range}`) ||
      (byName.get(name) || []).find(p => p.version === version);
    return exact ? [exact] : (byName.get(name) || []);
  };

  const roots = [];
  for (const manifest of manifests(directory)) {
    for (const [name, range] of Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies })) roots.push([name, range]);
  }
  for (const importer of Object.values(packages.importers || {})) {
    for (const [name, spec] of Object.entries({ ...importer.dependencies, ...importer.optionalDependencies })) roots.push([name, typeof spec === 'object' ? spec.version : spec]);
  }
  if (roots.length === 0) return; // nothing to tell runtime and development packages apart

  const runtime = new Set();
  const queue = roots.flatMap(([name, range]) => resolve(name, range));
  while (queue.length > 0) {
    const pkg = queue.pop();
    if (runtime.has(pkg)) continue;
    runtime.add(pkg);
    for (const [name, range] of Object.entries(pkg.dependencies || {})) queue.push(...resolve(name, range));
  }
  for (const pkg of packages) if (pkg.dev === undefined && !pkg.local) pkg.dev = !runtime.has(pkg);
}

/**
 * Lists the packages installed according to a lockfile, as [{ name, version, dev, line }], deduplicated by name@version.
 * For Yarn and pnpm lockfiles, which don't record it, `dev` is worked out from the project's package.json files.
 */
export function listLockfilePackages(filename, text) {
  const base = path.basename(filename).toLowerCase();
  let packages = [];
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') packages = npmPackages(JSON.parse(text));
  else if (base === 'yarn.lock') packages = yarnPackages(text);
  else if (base === 'pnpm-lock.yaml') packages = pnpmPackages(text);
  if (base === 'yarn.lock' || base === 'pnpm-lock.yaml') markDevPackages(packages, path.dirname(filename));

  const lines = text.split('\n');
  const unique = new Map();
  for (const pkg of packages) {
    if (!pkg.name || pkg.local || !valid(pkg.version)) continue;
    const key = `${pkg.name}@${pkg.version}`;
    if (unique.has(key)) {
      // a package counts as a runtime dependency if any copy of it is
      if (!pkg.dev) unique.get(key).dev = false;
      continue;
    }
    const index = lines.findIndex(l => l.includes(`node_modules/${pkg.name}"`) || l.includes(`${pkg.name}@`));
    unique.set(key, { name: pkg.name, version: pkg.version, dev: !!pkg.dev, line: index + 1 || 1 });
  }
  return [...unique.values()];
}
