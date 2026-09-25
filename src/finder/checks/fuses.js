// Electron Fuses (https://www.electronjs.org/docs/latest/tutorial/fuses): build-time switches that disable features at the binary level.
// `secure` is the value recommended by the Electron security checklist, `unsetIsInsecure` means Electron's default is the insecure value.
import { severity } from '../attributes.js';

export const FUSES = {
  RunAsNode: { secure: false, unsetIsInsecure: true, severity: severity.HIGH, risk: 'ELECTRON_RUN_AS_NODE lets anyone run the app binary as a plain Node.js process' },
  EnableNodeOptionsEnvironmentVariable: { secure: false, unsetIsInsecure: true, severity: severity.MEDIUM, risk: 'NODE_OPTIONS can inject code into the main process' },
  EnableNodeCliInspectArguments: { secure: false, unsetIsInsecure: true, severity: severity.MEDIUM, risk: '--inspect flags let a local attacker attach a debugger to the main process' },
  EnableEmbeddedAsarIntegrityValidation: { secure: true, unsetIsInsecure: true, severity: severity.MEDIUM, risk: 'app.asar can be modified without detection' },
  OnlyLoadAppFromAsar: { secure: true, unsetIsInsecure: true, severity: severity.MEDIUM, risk: 'the app can be loaded from an unpacked directory, bypassing ASAR integrity checks' },
  EnableCookieEncryption: { secure: true, unsetIsInsecure: true, severity: severity.LOW, risk: 'cookies are stored on disk unencrypted' },
  GrantFileProtocolExtraPrivileges: { secure: false, unsetIsInsecure: true, severity: severity.LOW, risk: 'pages loaded over file:// get extra privileges' },
};

const lowerFirst = (s) => s.charAt(0).toLowerCase() + s.slice(1);

// Accepts both `FuseV1Options.RunAsNode` (@electron/fuses, Electron Forge) and `runAsNode` (electron-builder `electronFuses`)
export function fuseName(key) {
  if (!key) return undefined;
  if (FUSES[key]) return key;
  return Object.keys(FUSES).find(name => lowerFirst(name) === key);
}

/**
 * Evaluates a fuse configuration given as { fuseName: value }.
 * Returns { insecure: [{ fuse, value }], unset: [fuse] }.
 */
export function evaluateFuses(config) {
  const insecure = [];
  const unset = [];
  for (const [fuse, rule] of Object.entries(FUSES)) {
    if (!(fuse in config)) {
      if (rule.unsetIsInsecure) unset.push(fuse);
    } else if (config[fuse] !== rule.secure) {
      insecure.push({ fuse, value: config[fuse] });
    }
  }
  return { insecure, unset };
}
