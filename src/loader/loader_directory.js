import fs from 'node:fs';
import path from 'node:path';

import { read_file, list_files } from '../util/index.js';
import { Loader } from './loader_interface.js';
import { findOldestElectronVersion } from "../util/electron_version.js";

function readIfExists(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
}

export class LoaderDirectory extends Loader {
  constructor() {
    super();
  }

  async load(dir, options = {}) {
    const files = await list_files(dir, options);

    for (const file of files) {
      this._loaded.add(file);
    }
    this._vendoredLibraries = files.vendoredLibraries || [];
    this._skipped = files.skipped || {};

    // Prefer the manifest closest to the root of the scanned directory
    const byDepth = [...files].sort((a, b) => a.split(path.sep).length - b.split(path.sep).length);
    const readAndOptionallyParse = (filename, shouldParse) => {
      try {
        const file = byDepth.find(f => path.basename(f) === filename);
        if (!file) return undefined;
        const content = this.load_buffer(file);
        return shouldParse ? JSON.parse(content) : content;
      } catch {
        return undefined;
      }
    };

    const electronVersion = await findOldestElectronVersion({
      pjsonData: readAndOptionallyParse('package.json', true),
      rootPath: dir,
      plockData: readAndOptionallyParse('package-lock.json', true) || readAndOptionallyParse('npm-shrinkwrap.json', true),
      yarnLockData: readAndOptionallyParse('yarn.lock', false),
      pnpmLockData: readAndOptionallyParse('pnpm-lock.yaml', false),
      npmrcData: readIfExists(path.join(dir, '.npmrc')),
    });
    if (electronVersion) this._electronVersion = electronVersion;
  }

  async stash() {
    this._loaded.clear();
    this._electronVersion = undefined;
    this._vendoredLibraries = [];
  }

  load_buffer(filename) {
    return read_file(filename);
  }
}
