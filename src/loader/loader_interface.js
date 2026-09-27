export class Loader {
  constructor() {
    this._loaded = new Set();
    this._electronVersion = undefined;
    this._vendoredLibraries = []; // { name, version, file } of skipped library copies
    this._skipped = {}; // how many files were left out, by reason
    this._installedPackages = []; // { name, version, file } shipped in a packaged app's node_modules
  }

  get list_files() { return this._loaded; }
  get electronVersion() { return this._electronVersion; }
  get vendoredLibraries() { return this._vendoredLibraries; }
  get skipped() { return this._skipped; }
  get installedPackages() { return this._installedPackages; }

  load_buffer(filename) {
    return undefined;
  }
}
