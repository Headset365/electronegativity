// Network access is optional: with --offline (or ELECTRONEGATIVITY_OFFLINE=1) the checks that need it are skipped
export class OfflineError extends Error {
  constructor() {
    super('offline mode');
    this.offline = true;
  }
}

export function isOffline() {
  return /^(1|true|yes)$/i.test(process.env.ELECTRONEGATIVITY_OFFLINE || '');
}

export function assertOnline() {
  if (isOffline()) throw new OfflineError();
}
