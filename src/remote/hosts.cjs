'use strict';
// --remote and --remote-header, shared by the CLI and the watch hook (which runs inside the app, so CommonJS).
//
// --remote names the only hosts the tool sends requests of its own to: full URLs (where crawling starts) or host names
// (crawled from their start page), '*.example.com' for any subdomain of example.com. Comma-separated and repeatable.
// --remote-header takes header names (Authorization, Cookie): their values are copied from the requests the app itself
// sends to each --remote host during a watch session. 'Name: value' still sets a header by hand.

// RFC 9110 token characters
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

const entries = (values) => [].concat(values || []).flatMap(value => String(value).split(',')).map(value => value.trim()).filter(Boolean);
const unique = (list) => [...new Set(list)];

/**
 * @returns {{ seeds: string[], guessed: string[], hosts: string[], invalid: string[] }} seeds: the URLs crawling starts
 * from; guessed: those of them made up from a host name (https://host/); hosts: the host names (lowercase, '*.' for
 * subdomains) the tool may fetch from; invalid: entries that are neither
 */
function parseRemote(values) {
  const seeds = [], given = [], guessed = [], hosts = [], invalid = [];
  for (const entry of entries(values)) {
    const isUrl = /^https?:\/\//i.test(entry);
    const wildcard = !isUrl && entry.startsWith('*.');
    let url;
    try {
      url = new URL(isUrl ? entry : `https://${wildcard ? entry.slice(2) : entry}`);
    } catch {
      invalid.push(entry);
      continue;
    }
    if (!url.hostname || url.username || url.password || (wildcard && url.href !== `https://${url.host}/`)) {
      invalid.push(entry);
      continue;
    }
    const host = url.hostname.toLowerCase();
    hosts.push(wildcard ? `*.${host}` : host);
    // a subdomain pattern names no page to start from
    if (!wildcard) seeds.push(url.href);
    if (!wildcard) (isUrl ? given : guessed).push(url.href);
  }
  // a start page also given as a URL is not a guess
  return { seeds: unique(seeds), guessed: unique(guessed).filter(url => !given.includes(url)), hosts: unique(hosts), invalid };
}

/** Whether the host of `url` (a URL or a host name) is one of `hosts`; '*.example.com' covers its subdomains only. */
function hostAllowed(url, hosts) {
  let host;
  try {
    host = (/^[a-z][a-z0-9+.-]*:\/\//i.test(String(url)) ? new URL(url).hostname : String(url)).toLowerCase();
  } catch {
    return false;
  }
  return !!host && hosts.some(pattern => pattern.startsWith('*.') ? host.endsWith(pattern.slice(1)) : host === pattern);
}

/**
 * @returns {{ fixed: Object<string,string>, names: string[], invalid: string[] }} fixed: 'Name: value' headers given by
 * hand; names: headers whose values are copied from the app's own requests
 */
function parseRemoteHeaders(values) {
  const fixed = {}, names = [], invalid = [];
  for (const value of [].concat(values || [])) {
    const text = String(value).trim();
    const at = text.indexOf(':');
    // a value can hold commas (cookies, Accept): 'Name: value' is taken whole
    if (at > 0) {
      const name = text.slice(0, at).trim();
      if (HEADER_NAME.test(name)) fixed[name] = text.slice(at + 1).trim();
      else invalid.push(text);
      continue;
    }
    for (const name of entries(text)) {
      if (!HEADER_NAME.test(name)) invalid.push(name);
      else if (!names.some(known => known.toLowerCase() === name.toLowerCase())) names.push(name);
    }
  }
  return { fixed, names, invalid };
}

/** The values of `names` in `headers` (an object of a request's headers), under the names as given. */
function pickHeaders(headers, names) {
  const picked = {};
  if (!headers || typeof headers !== 'object') return picked;
  const keys = Object.keys(headers);
  for (const name of names) {
    const key = keys.find(k => k.toLowerCase() === name.toLowerCase());
    if (key === undefined) continue;
    const value = headers[key];
    const text = Array.isArray(value) ? value.join(name.toLowerCase() === 'cookie' ? '; ' : ', ') : value === undefined || value === null ? '' : String(value);
    if (text) picked[name] = text;
  }
  return picked;
}

module.exports = { parseRemote, hostAllowed, parseRemoteHeaders, pickHeaders };
