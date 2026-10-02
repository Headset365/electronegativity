'use strict';
// Secret detection and redaction, shared by the traffic checks (HAR/Burp captures and watch mode, where it is loaded into
// the app's main process by hook.cjs), the data-at-rest review and the static secret checks. CommonJS and
// dependency-free so the watch hook can require it.

// Provider-specific patterns: specific enough to report on their own. The generic assignment patterns below are
// entropy-gated.
const SECRET_PATTERNS = [
  ['AWS access key id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
  ['Slack webhook', /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g],
  ['Stripe secret key', /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ['OpenAI API key', /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/g],
  ['Twilio API key', /\bSK[0-9a-fA-F]{32}\b/g],
  ['SendGrid API key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['Private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g],
  ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ['Azure storage connection string', /AccountKey=[A-Za-z0-9+/=]{40,}/g],
  ['Basic-auth credentials in URL', /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"]{1,64}:[^\s/@'"]{3,64}@[\w.-]+/g],
];

const SECRET_NAME = '[A-Za-z0-9_$.-]*(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token' +
  '|refresh[_-]?token|password|passwd|private[_-]?key|token)[A-Za-z0-9_$.-]*';
// name = 'value' / "name": "value" in code and JSON
const GENERIC_ASSIGN = new RegExp(`\\b(${SECRET_NAME})['"]?\\s*[:=]\\s*(['"\`])([^'"\`\\s]{12,200})\\2`, 'gi');
// config files only (.env / .ini / .properties / .yml): unquoted KEY=value / key: value
const CONFIG_ASSIGN = new RegExp(`^[ \\t]*(?:export[ \\t]+)?(${SECRET_NAME})[ \\t]*[:=][ \\t]*([^\\s'"\`#;]{12,200})[ \\t]*$`, 'gim');
// entropy check (config files only): any key with a long, random-looking value
const CONFIG_ANY = /["']?([A-Za-z_][A-Za-z0-9_.-]{1,60})["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{32,300})["']?\s*[,}\]]*\s*$/gm;
const HASH_KEYS = /integrity|resolved|checksum|hash|sha\d*|md5|digest|etag|version|uuid|guid|commit|revision|build|signature|fingerprint|nonce|salt|id$/i;

const PLACEHOLDER = /^(?:x+|\*+|0+|changeme|example|test|dummy|placeholder|your[_-]?.*|<.*>|\$\{.*\}|%.*%|\{\{.*\}\})$/i;
const UUIDISH = /^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/;

function shannonEntropy(text) {
  if (!text) return 0;
  const freq = new Map();
  for (const ch of text) freq.set(ch, (freq.get(ch) || 0) + 1);
  const n = [...text].length;
  let entropy = 0;
  for (const count of freq.values()) entropy -= count / n * Math.log2(count / n);
  return entropy;
}

/** Keeps a short prefix so evidence is recognisable but not reusable. */
function redact(value, keep = 4) {
  if (value === undefined || value === null) return '';
  const text = String(value);
  if (text.length <= keep + 2) return '*'.repeat(text.length);
  return `${text.slice(0, keep)}…[redacted ${text.length} chars]`;
}

const SENSITIVE_TOKENS = new Set(['token', 'secret', 'password', 'passwd', 'pwd', 'pass', 'apikey', 'session', 'sessionid', 'sessid',
  'sid', 'sig', 'signature', 'jwt', 'credential', 'credentials', 'private', 'privatekey', 'auth', 'authorization', 'bearer', 'otp',
  'hmac', 'nonce']);
const SENSITIVE_PAIRS = new Set(['api key', 'access key', 'secret key', 'client secret', 'private key', 'auth code', 'refresh token', 'id token']);

/** 'apiKey' / 'api_key' / 'X-Api-Key' -> ['api', 'key'] */
function paramTokens(name) {
  return String(name || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

/** Name-based: whole tokens only, so 'author', 'side', 'design' do not match. */
function isSensitiveParam(name) {
  const tokens = paramTokens(name);
  if (tokens.some(t => SENSITIVE_TOKENS.has(t))) return true;
  const joined = tokens.join('');
  if (SENSITIVE_TOKENS.has(joined) || ['apikey', 'accesstoken', 'clientsecret'].includes(joined)) return true;
  for (let i = 0; i + 1 < tokens.length; i++) if (SENSITIVE_PAIRS.has(`${tokens[i]} ${tokens[i + 1]}`)) return true;
  return false;
}

// values in code that are not credentials: a route or path (/login, /inbox/api-keys), a CSS or DOM selector
// ([type=password], #token-field), or a constant's own name in words (RequiredPassword, ResetPasswordToken)
const CODE_VALUE = /^(?:[/[.#@:~]|\w+:\/\/)|^(?:[A-Z]?[a-z]{2,}){3,}$|^[a-z]+(?:[-_][a-z]+){2,}$|^(?:[A-Z][A-Z]+_)+[A-Z]+$/;

function looksSecretValue(value) {
  const text = String(value || '');
  if (text.length < 12 || PLACEHOLDER.test(text) || text.includes(' ') || CODE_VALUE.test(text)) return false;
  return shannonEntropy(text) >= 3.3;
}

/** Value-only heuristic (URL parameters): long, high-entropy, and not a plain id or UUID. */
function looksRandomSecret(value) {
  const text = String(value || '');
  if (text.length < 24 || UUIDISH.test(text) || /^\d+$/.test(text)) return false;
  return looksSecretValue(text) && shannonEntropy(text) >= 4.0;
}

/**
 * [{ kind, value, offset }] for the secrets in `text`. `config` adds unquoted KEY=value assignments and an entropy check
 * on any key's value (for .env / .ini / .json / .yml files, not code); `patternsOnly` keeps the provider-specific
 * patterns (strings from binaries). Kinds starting with "Hard-coded" come from a secret-named assignment.
 */
function findSecrets(text, { maxHits = 50, config = false, patternsOnly = false } = {}) {
  const hits = [];
  const seen = new Set();
  const input = String(text || '');
  const add = (kind, value, offset) => {
    if (seen.has(value)) return hits.length >= maxHits;
    seen.add(value);
    hits.push({ kind, value, offset });
    return hits.length >= maxHits;
  };
  for (const [kind, pattern] of SECRET_PATTERNS) {
    for (const match of input.matchAll(pattern)) {
      if (kind === 'Basic-auth credentials in URL' && placeholderCredentials(match[0])) continue;
      if (add(kind, match[0], match.index)) return hits;
    }
  }
  if (patternsOnly) return hits;
  for (const match of input.matchAll(GENERIC_ASSIGN)) {
    const value = match[3];
    if (looksSecretValue(value) && add(`Hard-coded ${match[1]}`, value, match.index + match[0].lastIndexOf(value))) return hits;
  }
  if (!config) return hits;
  for (const match of input.matchAll(CONFIG_ASSIGN)) {
    const value = match[2];
    if (looksSecretValue(value) && !value.includes('(') && add(`Hard-coded ${match[1]}`, value, match.index + match[0].lastIndexOf(value))) return hits;
  }
  for (const match of input.matchAll(CONFIG_ANY)) {
    const [, key, value] = match;
    if (HASH_KEYS.test(key) || /^(sha|http)/.test(value) || /^[0-9a-fA-F]+$/.test(value)) continue;
    const wordy = (value.match(/[a-z]{4,}/g) || []).reduce((sum, w) => sum + w.length, 0) / value.length;
    if (wordy >= 0.4) continue; // CamelCaseIdentifiersAndWords, not random data
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(p => p.test(value)).length;
    if (classes >= 3 && shannonEntropy(value) >= 4.3 && add(`High-entropy value (${key})`, value, match.index + match[0].lastIndexOf(value))) return hits;
  }
  return hits;
}

// Suppress only explicit user/password templates, not a real password paired with a generic-looking user.
function placeholderCredentials(value) {
  const credentials = value.match(/:\/\/([^:]+):([^@]+)@/);
  if (!credentials) return false;
  const decode = text => { try { return decodeURIComponent(text); } catch { return text; } };
  const user = decode(credentials[1]), password = decode(credentials[2]);
  // both halves template words: username:password, user:pass, [user]:[password], <user>:<pass>, foo:bar, ${USER}:${PASS}
  const word = /^(?:[[<{(]|\$\{|%|:)?\s*(?:user(?:[_-]?name)?|login|name|pass(?:word)?|pwd|secret|foo|bar|baz|test|demo|example|x+|\*+|your[_-]?\w*|my[_-]?\w*)\s*(?:[\]>})%])?$/i;
  return word.test(user) && word.test(password);
}

/** Redacts every provider-pattern secret inside free-form text. */
function redactText(text) {
  let out = String(text || '');
  for (const [, pattern] of SECRET_PATTERNS) out = out.replace(pattern, match => redact(match));
  return out;
}

const AUTH_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-access-token', 'x-csrf-token',
  'x-xsrf-token', 'x-amz-security-token', 'api-key', 'apikey']);

function isAuthHeader(name) {
  const n = String(name || '').toLowerCase();
  return AUTH_HEADERS.has(n) || (n.includes('token') && n.startsWith('x-')) || n.endsWith('-api-key');
}

module.exports = { SECRET_PATTERNS, shannonEntropy, redact, redactText, paramTokens, isSensitiveParam, looksSecretValue, looksRandomSecret,
  findSecrets, isAuthHeader };
