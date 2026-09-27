import { Loader } from './loader_interface.js';

// The app's own files plus other folders scanned with them (front-end code captured from a server): one list of
// files, each read by the loader it came from. The Electron version and manifest come from the primary loader.
export class LoaderCombined extends Loader {
  constructor(primary, extras) {
    super();
    this._owners = new Map();
    for (const loader of [primary, ...extras]) {
      for (const file of loader.list_files) {
        if (this._owners.has(file)) continue;
        this._owners.set(file, loader);
        this._loaded.add(file);
      }
    }
    this._electronVersion = primary.electronVersion;
    this._vendoredLibraries = [primary, ...extras].flatMap(loader => loader.vendoredLibraries || []);
    this._installedPackages = [primary, ...extras].flatMap(loader => loader.installedPackages || []);
    for (const loader of [primary, ...extras]) {
      for (const [reason, count] of Object.entries(loader.skipped || {})) this._skipped[reason] = (this._skipped[reason] || 0) + count;
    }
  }

  load_buffer(filename) {
    const owner = this._owners.get(filename);
    return owner ? owner.load_buffer(filename) : undefined;
  }
}
