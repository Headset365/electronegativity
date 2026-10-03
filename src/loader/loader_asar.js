import path from 'node:path';
import * as asar from '@electron/asar';

import logger from '../util/logger.js';
import { isScannableFile, isNonAppFile, vendoredLibrary, installedPackages } from '../util/index.js';
import { Loader } from './loader_interface.js';
import { findOldestElectronVersion } from "../util/electron_version.js";

export class LoaderAsar extends Loader {
  constructor() {
    super();
  }

  // returns map filename -> content
  async load(archive, { allFiles = false } = {}) {
    this.archive = archive;

    const archived_files = asar.listPackage(archive, { isPack: false })
      .map(file => file.startsWith(path.sep) ? file.substring(1) : file)
      .filter(file => { const stat = asar.statFile(archive, file); return !stat.files && !stat.link; });
    logger.debug(`Files in ASAR archive: ${archived_files}`);

    // an app.asar is what ships: all of it is app code (see isNonAppFile), and the packages in its node_modules are
    // the app's dependencies, as there is no lockfile
    this._installedPackages = installedPackages(archived_files.filter(f => path.basename(f) === 'package.json' && f.split(/[\\/]/).includes('node_modules')),
      (file) => this.load_buffer(file).toString());
    for (const f of archived_files) {
      if (f.split(path.sep).includes('node_modules')) continue;
      if (!isScannableFile(f)) continue;
      if (!allFiles && isNonAppFile(f, { packaged: true })) {
        this._skipped.nonAppFiles = (this._skipped.nonAppFiles || 0) + 1;
        continue;
      }
      if (!allFiles && this.isVendored(f)) {
        this._skipped.vendoredLibraries = (this._skipped.vendoredLibraries || 0) + 1;
        continue;
      }
      this._loaded.add(f);
    }

    const readAndOptionallyParse = (filename, shouldParse) => {
      try {
        const file = archived_files.find(f => path.basename(f) === filename && !f.split(path.sep).includes('node_modules'));
        if (!file) return undefined;
        const content = this.load_buffer(file).toString();
        return shouldParse ? JSON.parse(content) : content;
      } catch {
        return undefined;
      }
    };

    const electronVersion = await findOldestElectronVersion({
      pjsonData: readAndOptionallyParse('package.json', true),
      plockData: readAndOptionallyParse('package-lock.json', true) || readAndOptionallyParse('npm-shrinkwrap.json', true),
      yarnLockData: readAndOptionallyParse('yarn.lock', false),
      pnpmLockData: readAndOptionallyParse('pnpm-lock.yaml', false),
    });
    if (electronVersion) this._electronVersion = electronVersion;

    logger.debug(`Discovered ${this.list_files.size} files`);
  }

  isVendored(file) {
    if (!/\.[cm]?js$/i.test(file)) return false;
    try {
      const library = vendoredLibrary(file, this.load_buffer(file).subarray(0, 2048).toString());
      if (library) this._vendoredLibraries.push({ ...library, file });
      return !!library;
    } catch {
      return false;
    }
  }

  load_buffer(filename) {
    logger.debug(`Extracting file: ${filename}`);
    return asar.extractFile(this.archive, filename);
  }
}
