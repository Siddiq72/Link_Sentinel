/**
 * Evaluates host for raw IP addresses and obfuscated numerical encodings.
 * Flags:
 * - Raw public IPv4/IPv6 and obfuscated hex/octal representations as "suspicious"
 * - RFC 1918 private IP ranges as "review"
 */

import { isIpv4, isIpv6 } from '../domain.js';

/**
 * Checks if an IPv4 address is within RFC 1918 private ranges:
 * - 10.0.0.0 - 10.255.255.255 (10/8)
 * - 172.16.0.0 - 172.31.255.255 (172.16/12)
 * - 192.168.0.0 - 192.168.255.255 (192.168/16)
 * Also covers loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
 */
export function isPrivateIp(ip) {
  if (!isIpv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/**
 * Checks if raw host text contains obfuscated numeric IP formats (hex, octal, dword).
 */
export function isObfuscatedIp(rawInput, hostname) {
  if (!rawInput || typeof rawInput !== 'string') return false;
  try {
    const rawMatch = rawInput.match(/^[a-zA-Z]+:\/\/([^/?#:]+)/i) || rawInput.match(/^([^/?#:]+)/);
    const hostPart = rawMatch ? rawMatch[1] : '';

    // Check for hex (0x...), octal (0177... or leading zeros in octets), or single integer dword
    const hasHex = /0x[0-9a-fA-F]+/i.test(hostPart);
    const hasOctal = /\b0[0-7]+\b/.test(hostPart) && hostPart.includes('.');
    const isDword = /^\d+$/.test(hostPart) && isIpv4(hostname);

    return hasHex || hasOctal || isDword;
  } catch {
    return false;
  }
}

export function evaluateIpRule(parsedContext) {
  const { url, rawInput = '', domainInfo } = parsedContext;
  const hostname = domainInfo?.hostname || url.hostname || '';
  const rules = [];
  const anomalies = [];

  const isObfuscated = isObfuscatedIp(rawInput, hostname);
  const isIp = domainInfo?.isIp || isIpv4(hostname) || isIpv6(hostname);

  if (isObfuscated) {
    rules.push({
      id: 'obfuscated-ip-host',
      name: 'Obfuscated Numerical IP Host',
      severity: 'suspicious',
      reason: 'Flagged: host uses hex, octal, or integer encoding to disguise an IP address.'
    });
    anomalies.push('raw_ip_host');
    anomalies.push('obfuscated_ip');
  } else if (isIp) {
    if (isPrivateIp(hostname) || hostname === '[::1]' || hostname === '::1') {
      rules.push({
        id: 'private-ip-host',
        name: 'Private Network IP Host',
        severity: 'review',
        reason: 'Host is a private local area network IP address (RFC 1918). Destination only accessible on internal networks.'
      });
      anomalies.push('private_ip_host');
    } else {
      rules.push({
        id: 'ip-host-detection',
        name: 'Direct IP Address Authority',
        severity: 'suspicious',
        reason: 'Flagged: host is an unmapped numerical IP address instead of a verified domain name.'
      });
      anomalies.push('raw_ip_host');
    }
  }

  return { rules, anomalies };
}

export default evaluateIpRule;
