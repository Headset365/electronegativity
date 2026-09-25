import path from 'node:path';
import fs from 'node:fs';

import { read_file } from '../util/index.js';
import { Loader } from './loader_interface.js';

export class LoaderFile extends Loader {
  constructor() {
    super();
  }

  load(file) {
    const filename = path.resolve(file);
    if (!fs.existsSync(filename))
      throw new Error(`File ${filename} not found.`);
    this._loaded.add(filename);
  }

  load_buffer(filename) {
    const buffer = read_file(filename);
    return buffer;
  }
}
