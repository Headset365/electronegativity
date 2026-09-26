export class Loader {
  constructor() {
    this._loaded = new Set();
    this._electronVersion = undefined;
    this._vendoredLibraries = []; // { name, version, file } of skipped library copies
    this._skipped = {}; // how many files were left out, by reason
  }

  get list_files() { return this._loaded; }
  get electronVersion() { return this._electronVersion; }
  get vendoredLibraries() { return this._vendoredLibraries; }
  get skipped() { return this._skipped; }

  load_buffer(filename) {
    return undefined;
  }
}
