import crypto from 'node:crypto';
import path from 'node:path';
import { Loader } from './loader_interface.js';

const CODE = /\.(?:[cm]?jsx?|html?)$/i;
const digest = (buffer) => buffer ? crypto.createHash('sha256').update(buffer).digest('hex') : undefined;

// The app's own files plus other folders scanned with them (front-end code captured from a server): one list of
// files, each read by the loader it came from. The Electron version and manifest come from the primary loader.
export class LoaderCombined extends Loader {
  constructor(primary, extras) {
    super();
    this._owners = new Map();
    // a captured file identical to one in the package is the package's own copy, served to the page by the app (a
    // protocol.handle('https') handler, an app:// scheme): scanning it again would only repeat the package's findings
    // the package: the primary loader and the web folders shipped next to it (resources/stage), marked isPackage
    const packageLoaders = [primary, ...extras.filter(loader => loader.isPackage)];
    const packaged = new Map();
    const ownerOf = new Map();
    for (const loader of packageLoaders) for (const file of loader.list_files) {
      if (!CODE.test(file)) continue;
      const name = path.basename(file).toLowerCase();
      if (!packaged.has(name)) packaged.set(name, []);
      packaged.get(name).push(file);
      ownerOf.set(file, loader);
    }
    const hashes = new Map();
    const hashOf = (file) => {
      if (!hashes.has(file)) hashes.set(file, digest(ownerOf.get(file).load_buffer(file)));
      return hashes.get(file);
    };
    this.duplicatesOfPackage = [];
    for (const loader of [primary, ...extras]) {
      for (const file of loader.list_files) {
        if (this._owners.has(file)) continue;
        if (!packageLoaders.includes(loader) && CODE.test(file)) {
          // a URL path keeps the file name (assets/app-Cz….js), a query string or extension change does not
          const candidates = packaged.get(path.basename(file).replace(/_[0-9a-f]{8}(?=\.\w+$)/, '').toLowerCase()) || [];
          const hash = candidates.length ? digest(loader.load_buffer(file)) : undefined;
          if (hash && candidates.some(candidate => hashOf(candidate) === hash)) {
            this.duplicatesOfPackage.push(file);
            continue;
          }
        }
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
