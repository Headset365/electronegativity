import path from 'node:path';
import * as asar from '@electron/asar';

import logger from '../util/logger.js';
import { isScannableFile } from '../util/index.js';
import { Loader } from './loader_interface.js';
import { findOldestElectronVersion } from "../util/electron_version.js";

export class LoaderAsar extends Loader {
  constructor() {
    super();
  }

  // returns map filename -> content
  async load(archive) {
    this.archive = archive;

    const archived_files = asar.listPackage(archive, { isPack: false })
      .map(file => file.startsWith(path.sep) ? file.substring(1) : file);
    logger.debug(`Files in ASAR archive: ${archived_files}`);

    for (const f of archived_files) {
      if (f.split(path.sep).includes('node_modules')) continue;
      if (isScannableFile(f)) this._loaded.add(f);
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

  load_buffer(filename) {
    logger.debug(`Extracting file: ${filename}`);
    return asar.extractFile(this.archive, filename);
  }
}
