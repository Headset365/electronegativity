// What an unpacked installer says about the app: whether the installer itself is signed, and the URL protocols and file
// types it registers (deep links and file associations: entry points for content from outside the app).
import path from 'node:path';
import { severity, confidence } from '../finder/attributes.js';
import { verifySignature, NOT_SIGNED, VALID } from '../binary/signature.js';

const issue = (id, file, sev, conf, description, properties, reference) => ({
  file, sample: '', location: { line: 0, column: 0 }, id, description, properties, shortenedURL: reference, severity: sev, confidence: conf,
  manualReview: false, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime',
});

/** @param {Object} unpacked unpackTarget()'s result */
export function installerIssues(unpacked, { signing = true, platform, run } = {}) {
  const issues = [];
  const file = unpacked.target;
  const name = path.basename(file);
  if (signing && unpacked.installer.pe) {
    const signature = verifySignature(file, { platform, run });
    if (signature.status === NOT_SIGNED)
      issues.push(issue('CODE_SIGNING', file, severity.MEDIUM, confidence.CERTAIN, `The installer ${name} is not code-signed: users cannot tell it from a modified copy, and SmartScreen warns`,
        { status: signature.status, installer: true }, 'https://www.electronjs.org/docs/latest/tutorial/code-signing'));
    else if (signature.verifiedBy !== 'none' && signature.status !== VALID)
      issues.push(issue('CODE_SIGNING', file, signature.status === 'HashMismatch' ? severity.HIGH : severity.MEDIUM, confidence.CERTAIN,
        `The installer ${name}: the operating system reports the signature as ${signature.status}${signature.message ? `: ${signature.message}` : ''}`, { status: signature.status, signer: signature.signer, installer: true },
        'https://www.electronjs.org/docs/latest/tutorial/code-signing'));
    else
      issues.push(issue('CODE_SIGNING', file, severity.INFORMATIONAL, signature.verifiedBy === 'none' ? confidence.FIRM : confidence.CERTAIN,
        `The installer ${name} is signed${signature.signer ? ` by ${signature.signer}` : ''}: ${signature.verifiedBy === 'none' ? signature.message : `the operating system reports ${signature.status}`}`,
        { status: signature.status, signer: signature.signer, installer: true }, 'https://www.electronjs.org/docs/latest/tutorial/code-signing'));
  }
  const nsis = unpacked.installer.nsis;
  if (nsis && (nsis.protocols.length > 0 || nsis.extensions.length > 0)) {
    const parts = [nsis.protocols.length ? `URL protocol${nsis.protocols.length > 1 ? 's' : ''} ${nsis.protocols.map(p => `${p}://`).join(', ')}` : '',
      nsis.extensions.length ? `file type${nsis.extensions.length > 1 ? 's' : ''} ${nsis.extensions.join(', ')}` : ''].filter(Boolean);
    issues.push(issue('INSTALLER_FILE_HANDLER', file, severity.INFORMATIONAL, confidence.CERTAIN,
      `The installer registers the app for the ${parts.join(' and ')}: links and files from anywhere (a web page, an email, a shared folder) start the app with arguments they choose; check how its open-url, second-instance and command-line handling treats them`,
      { protocols: nsis.protocols, extensions: nsis.extensions }, 'https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app'));
  }
  return issues;
}
