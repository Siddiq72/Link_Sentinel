/**
 * Domain parsing and Unicode/Punycode normalization module.
 * Uses psl (Public Suffix List) for registrable domain identification.
 */

import psl from 'psl';

/**
 * Decodes a single Punycode label (RFC 3492).
 * 
 * @param {string} input - Label, e.g. "xn--ampus-0ye"
 * @returns {string} Decoded Unicode string, e.g. "сampus"
 */
export function decodePunycodeLabel(input) {
  if (!input || !input.toLowerCase().startsWith('xn--')) return input;
  const str = input.slice(4);
  const output = [];
  const lastDelim = str.lastIndexOf('-');
  const basic = lastDelim > 0 ? str.slice(0, lastDelim) : '';

  for (let j = 0; j < basic.length; j++) {
    output.push(basic.charCodeAt(j));
  }

  let pos = lastDelim > 0 ? lastDelim + 1 : 0;
  let n = 128;
  let i = 0;
  let bias = 72;

  while (pos < str.length) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (pos >= str.length) break;
      const c = str.charCodeAt(pos++);
      let digit;
      if (c >= 48 && c <= 57) digit = c - 22; // 0-9
      else if (c >= 65 && c <= 90) digit = c - 65; // A-Z
      else if (c >= 97 && c <= 122) digit = c - 97; // a-z
      else digit = 36;

      i += digit * w;
      const t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
      if (digit < t) break;
      w *= (36 - t);
    }

    const delta = (oldi === 0) ? Math.floor(i / 700) : Math.floor((i - oldi) / 2);
    let deltaCalc = delta + Math.floor(delta / (output.length + 1));
    let k = 0;
    while (deltaCalc > Math.floor((35 * 26) / 2)) {
      deltaCalc = Math.floor(deltaCalc / 35);
      k += 36;
    }
    bias = k + Math.floor((36 * deltaCalc) / (deltaCalc + 38));
    n += Math.floor(i / (output.length + 1));
    i = i % (output.length + 1);
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

/**
 * Converts a hostname with Punycode labels into its full Unicode representation.
 * @param {string} hostname 
 * @returns {string}
 */
export function toUnicode(hostname) {
  if (!hostname || typeof hostname !== 'string') return '';
  return hostname.split('.').map(decodePunycodeLabel).join('.');
}

/**
 * Converts a Unicode hostname to its Punycode ASCII equivalent via WHATWG URL.
 * @param {string} hostname 
 * @returns {string}
 */
export function toAscii(hostname) {
  if (!hostname || typeof hostname !== 'string') return '';
  try {
    return new URL('http://' + hostname).hostname;
  } catch {
    return hostname.toLowerCase();
  }
}

/**
 * Validates whether the given host string is a dotted-decimal IPv4 address.
 * @param {string} host 
 * @returns {boolean}
 */
export function isIpv4(host) {
  if (!host || typeof host !== 'string') return false;
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

/**
 * Validates whether the given host string is an IPv6 address.
 * @param {string} host 
 * @returns {boolean}
 */
export function isIpv6(host) {
  if (!host || typeof host !== 'string') return false;
  if (host.startsWith('[') && host.endsWith(']')) return true;
  return host.includes(':') && /^[0-9a-fA-F:]+$/.test(host);
}

/**
 * Analyzes a hostname to extract registrable domain, unicode decoding, and PSL metadata.
 * 
 * @param {string} hostname - The URL hostname.
 * @returns {object} Domain analysis metadata.
 */
export function analyzeDomain(hostname) {
  if (!hostname) {
    return {
      hostname: '',
      unicodeHostname: '',
      asciiHostname: '',
      isIp: false,
      domain: '',
      registrableDomain: ''
    };
  }

  const cleanHost = hostname.toLowerCase();
  const unicodeHostname = toUnicode(cleanHost);
  const asciiHostname = toAscii(unicodeHostname);
  const isIp = isIpv4(cleanHost) || isIpv6(cleanHost);

  if (isIp) {
    return {
      hostname: cleanHost,
      unicodeHostname: cleanHost,
      asciiHostname: cleanHost,
      isIp: true,
      domain: cleanHost,
      registrableDomain: `${cleanHost} (Raw IP Authority)`
    };
  }

  const parsed = psl.parse(unicodeHostname);
  const domain = parsed.domain || unicodeHostname;
  let registrableDomain = domain;

  if (asciiHostname !== unicodeHostname) {
    const asciiParsed = psl.parse(asciiHostname);
    const asciiDomain = asciiParsed.domain || asciiHostname;
    registrableDomain = `${domain} (Punycode: ${asciiDomain})`;
  }

  return {
    hostname: cleanHost,
    unicodeHostname,
    asciiHostname,
    isIp: false,
    domain,
    registrableDomain,
    tld: parsed.tld,
    sld: parsed.sld,
    subdomain: parsed.subdomain
  };
}

export default {
  analyzeDomain,
  decodePunycodeLabel,
  toUnicode,
  toAscii,
  isIpv4,
  isIpv6
};
