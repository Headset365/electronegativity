// Launches the app under test with the observation hook loaded into its main process, and waits for it to close.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const HOOK = path.join(import.meta.dirname, 'hook.cjs');
const exists = (file) => {
  try {
    fs.accessSync(file);
    return true;
  } catch {
    return false;
  }
};

/**
 * How to start the app: a project folder is run with its own Electron (node_modules/electron), a packaged app by its
 * executable. Also returns the code to scan statically: the folder, or the resources/app.asar of a packaged app.
 * @returns {{ command, args, staticInput }}
 */
export function resolveApp(target, extraArgs = []) {
  const resolved = path.resolve(target);
  if (!exists(resolved)) throw new Error(`${target} does not exist`);
  const stat = fs.statSync(resolved);

  if (stat.isDirectory() && resolved.endsWith('.app')) { // macOS bundle
    const macos = path.join(resolved, 'Contents', 'MacOS');
    const executable = fs.readdirSync(macos).find(name => !name.startsWith('.'));
    const asar = path.join(resolved, 'Contents', 'Resources', 'app.asar');
    return { command: path.join(macos, executable), args: extraArgs, staticInput: exists(asar) ? asar : undefined, packaged: true };
  }
  if (stat.isDirectory()) {
    if (!exists(path.join(resolved, 'package.json'))) throw new Error(`${target} has no package.json: pass the app folder or its packaged executable`);
    let electron;
    try {
      electron = createRequire(path.join(resolved, 'package.json'))('electron');
    } catch {
      throw new Error(`Electron is not installed in ${target}: run npm install there, or pass the packaged executable`);
    }
    // a development folder runs the shared Electron binary, whose fuses are not the app's: no binary fuse reading
    return { command: electron, args: [resolved, ...extraArgs], staticInput: resolved, packaged: false };
  }
  const resources = path.join(path.dirname(resolved), 'resources');
  const asar = path.join(resources, 'app.asar');
  const unpacked = path.join(resources, 'app');
  return { command: resolved, args: extraArgs, staticInput: exists(asar) ? asar : exists(unpacked) ? unpacked : undefined, packaged: true };
}

/**
 * Starts the app with the hook and resolves with the path of the log once the app has exited.
 * The user drives the app; Ctrl+C in the terminal closes it too.
 */
export function watchApp(target, { args = [], marker, log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-watch-')), 'session.jsonl'), stdio = 'inherit' } = {}) {
  const { command, args: commandArgs } = resolveApp(target, args);
  fs.writeFileSync(log, '');
  const quotedHook = HOOK.includes(' ') ? `"${HOOK}"` : HOOK;
  const env = {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ? process.env.NODE_OPTIONS + ' ' : ''}--require ${quotedHook}`,
    ELECTRONEGATIVITY_WATCH_LOG: log,
  };
  if (marker) env.ELECTRONEGATIVITY_WATCH_MARKER = String(marker);
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, { env, stdio });
    const stop = () => child.kill();
    process.once('SIGINT', stop);
    child.once('error', (error) => {
      process.removeListener('SIGINT', stop);
      reject(error);
    });
    child.once('exit', () => {
      process.removeListener('SIGINT', stop);
      resolve(log);
    });
  });
}
