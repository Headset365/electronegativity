export class Loader {
  constructor() {
    this._loaded = new Set();
    this._electronVersion = undefined;
    this._vendoredLibraries = []; // { name, version, file } of skipped library copies
  }

  get list_files() { return this._loaded; }
  get electronVersion() { return this._electronVersion; }
  get vendoredLibraries() { return this._vendoredLibraries; }

  load_buffer(filename) {
    return undefined;
  }
}
