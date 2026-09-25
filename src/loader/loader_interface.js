export class Loader {
  constructor() {
    this._loaded = new Set();
    this._electronVersion = undefined;
  }

  get list_files() { return this._loaded; }
  get electronVersion() { return this._electronVersion; }

  load_buffer(filename) {
    return undefined;
  }
}
