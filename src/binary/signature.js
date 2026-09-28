// Code signatures of a packaged app's executable. On Windows the operating system verifies the Authenticode signature
// (PowerShell Get-AuthenticodeSignature: chain, trust and file hash); on macOS `codesign --verify` does. Elsewhere only
// its presence and the signer it names can be read, and the result says so rather than implying it was verified.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { parsePe, certificateBlob, isPe } from './pe.js';
import { machoInfo } from './macho.js';

export const VALID = 'Valid';
export const NOT_SIGNED = 'NotSigned';

// one DER element at `at`: { tag, at, start (of the content), end }
function tlv(data, at) {
  const tag = data[at];
  let length = data[at + 1];
  let start = at + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4) throw new Error('unsupported DER length');
    length = data.readUIntBE(at + 2, bytes);
    start += bytes;
  }
  if (start + length > data.length) throw new Error('truncated DER');
  return { tag, at, start, end: start + length };
}

function children(data, element) {
  const out = [];
  for (let at = element.start; at < element.end;) {
    const child = tlv(data, at);
    out.push(child);
    at = child.end;
  }
  return out;
}

/** The certificates carried in a PKCS#7 SignedData blob, as X509Certificate objects. */
export function pkcs7Certificates(blob) {
  try {
    const contentInfo = tlv(blob, 0);
    const [, explicit] = children(blob, contentInfo); // OID signedData, [0] EXPLICIT SignedData
    const signedData = children(blob, explicit)[0];
    const set = children(blob, signedData).find(e => e.tag === 0xa0); // certificates [0] IMPLICIT
    if (!set) return [];
    return children(blob, set).filter(e => e.tag === 0x30).map(e => new crypto.X509Certificate(blob.subarray(e.at, e.end)));
  } catch {
    return [];
  }
}

/** The signer's subject: the leaf, the one certificate in the blob that issued none of the others. */
export function signerOf(blob) {
  const certificates = pkcs7Certificates(blob);
  if (certificates.length === 0) return undefined;
  const issuers = new Set(certificates.map(c => c.issuer));
  const leaves = certificates.filter(c => !issuers.has(c.subject));
  return (leaves[0] || certificates[0]).subject.replace(/\n/g, ', ');
}

const psQuote = (text) => `'${String(text).replace(/'/g, '\'\'')}'`;

/**
 * { status, message, signer, verifiedBy: 'windows'|'macos'|'none', format: 'pe'|'macho'|undefined }
 * status: Valid | NotSigned | HashMismatch | NotTrusted | ... (verified by the OS), Present (seen, not verified), Unknown
 */
export function verifySignature(file, { platform = process.platform, run = spawnSync } = {}) {
  const result = { status: 'Unknown', message: '', signer: undefined, verifiedBy: 'none' };
  let data;
  try {
    data = fs.readFileSync(file);
  } catch (error) {
    return { ...result, message: `unreadable: ${error.message}` };
  }
  if (isPe(data)) {
    result.format = 'pe';
    let info;
    try {
      info = parsePe(data, { resources: false });
    } catch (error) {
      return { ...result, message: `not a readable PE file: ${error.message}` };
    }
    if (!info.signed) return { ...result, status: NOT_SIGNED, message: 'no Authenticode signature' };
    result.signer = signerOf(certificateBlob(data, info) || Buffer.alloc(0));
    if (platform === 'win32') {
      const command = `$s = Get-AuthenticodeSignature -LiteralPath ${psQuote(file)}; [pscustomobject]@{Status=[string]$s.Status; Message=$s.StatusMessage; Signer=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null })} | ConvertTo-Json -Compress`;
      const ps = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8', timeout: 60000, windowsHide: true });
      if (ps && ps.status === 0 && ps.stdout && ps.stdout.trim()) {
        try {
          const parsed = JSON.parse(ps.stdout.trim().split(/\r?\n/).pop());
          return { ...result, status: parsed.Status || 'Unknown', message: parsed.Message || '', signer: parsed.Signer || result.signer, verifiedBy: 'windows' };
        } catch {
          // fall through: presence only
        }
      }
      result.message = `Windows verification unavailable (${String((ps && (ps.stderr || ps.stdout)) || (ps && ps.error && ps.error.message) || '').trim().slice(0, 160)})`;
    }
    return { ...result, status: 'Present', message: result.message || 'signature present; trust not verified on this host (not Windows)' };
  }
  const macho = machoInfo(data);
  if (macho) {
    result.format = 'macho';
    if (!macho.codeSignature) return { ...result, status: NOT_SIGNED, message: 'no LC_CODE_SIGNATURE load command' };
    if (platform === 'darwin') {
      const bundle = file.match(/^(.*\.app)\//);
      const target = bundle ? bundle[1] : file;
      const check = run('codesign', ['--verify', '--deep', '--strict', target], { encoding: 'utf8', timeout: 120000 });
      if (check && typeof check.status === 'number') {
        const info = run('codesign', ['-dvv', target], { encoding: 'utf8', timeout: 30000 });
        const authority = ((info && info.stderr) || '').match(/^Authority=(.+)$/m);
        const adhoc = /Signature=adhoc/.test((info && info.stderr) || '');
        return { ...result, status: check.status === 0 ? (adhoc ? 'AdHoc' : VALID) : 'Invalid', message: (check.stderr || '').trim().slice(0, 300), signer: authority ? authority[1] : adhoc ? 'ad-hoc' : undefined, verifiedBy: 'macos' };
      }
    }
    return { ...result, status: 'Present', message: 'code signature present; not verified on this host (not macOS)' };
  }
  return { ...result, message: 'not a PE or Mach-O file' };
}
