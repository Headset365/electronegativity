import { gte, coerce } from 'semver';

// Electron releases in which security-relevant behaviour changed
export const ELECTRON_CHANGES = {
  AFFINITY_REMOVED: '14.0.0',         // webPreferences.affinity removed together with process reuse opt-out
  NEW_WINDOW_EVENT_REMOVED: '22.0.0', // webContents 'new-window' event removed, replaced by setWindowOpenHandler
  WILL_FRAME_NAVIGATE_ADDED: '25.0.0',
};

// True when the (possibly unknown) Electron version is at least `version`. Unknown versions are treated as the oldest.
export function electronAtLeast(electronVersion, version) {
  const v = coerce(electronVersion);
  return v ? gte(v, version) : false;
}
