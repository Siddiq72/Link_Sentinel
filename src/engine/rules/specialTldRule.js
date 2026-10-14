/**
 * RESERVED & SPECIAL-USE TLD GUARD (RFC 2606 / RFC 6761)
 *
 * Detects domains terminating in permanently reserved, special-use top-level domains:
 * .invalid, .test, .example, .localhost
 *
 * These domains cannot be registered or resolved on the public Internet.
 * Domains in documented safe contexts (e.g. campus.example) are preserved.
 */

import { PROTECTED_DOMAINS } from '../data/protectedDomains.js';
import { isIpv4, isIpv6 } from '../domain.js';

export const RESERVED_TLDS = ['invalid', 'test', 'example', 'localhost'];
const RESERVED_TLDS_SET = new Set(RESERVED_TLDS);

export const SAFE_DOCUMENTATION_DOMAINS = [
  'campus.example',
  'other.example',
  'example.com',
  'example.org',
  'example.net'
];

/**
 * Checks whether a domain has explicit safe documentation context under RFC 2606.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function isSafeDocumentationContext(hostname) {
  if (!hostname) return false;
  const clean = hostname.toLowerCase().replace(/\.+$/, '');

  if (SAFE_DOCUMENTATION_DOMAINS.includes(clean)) return true;
  if (PROTECTED_DOMAINS.includes(clean)) return true;

  for (const docDomain of SAFE_DOCUMENTATION_DOMAINS) {
    if (clean.endsWith('.' + docDomain)) return true;
  }
  for (const protDomain of PROTECTED_DOMAINS) {
    if (clean.endsWith('.' + protDomain)) return true;
  }

  return false;
}

/**
 * Checks if a hostname or domainInfo uses a reserved or special-use TLD.
 *
 * @param {object|string} domainInput - domainInfo object or hostname string
 * @param {string} [rawHost] - Optional fallback hostname string
 * @returns {object} Detection result
 */
export function checkSpecialTld(domainInput, rawHost) {
  let hostname = '';
  let domainInfo = null;

  if (typeof domainInput === 'string') {
    hostname = domainInput;
  } else if (domainInput) {
    domainInfo = domainInput;
    hostname = domainInfo.unicodeHostname || domainInfo.hostname || '';
  }

  if (!hostname && rawHost) {
    hostname = rawHost;
  }

  if (!hostname) {
    return { triggered: false };
  }

  let cleanHost = hostname.toLowerCase().trim();
  while (cleanHost.endsWith('.') && cleanHost.length > 1) {
    cleanHost = cleanHost.slice(0, -1);
  }

  // Raw IP addresses are handled by IP rules, not TLD checks
  if (domainInfo?.isIp || isIpv4(cleanHost) || isIpv6(cleanHost)) {
    return { triggered: false };
  }

  // Extract the terminal TLD component
  let tld = '';
  if (domainInfo?.tld) {
    tld = domainInfo.tld.toLowerCase();
  } else if (cleanHost.includes('.')) {
    const parts = cleanHost.split('.');
    tld = parts[parts.length - 1];
  } else if (cleanHost === 'localhost') {
    tld = 'localhost';
  }

  if (!tld || !RESERVED_TLDS_SET.has(tld)) {
    return { triggered: false };
  }

  // For .example, exempt explicit safe documentation context
  if (tld === 'example' && isSafeDocumentationContext(cleanHost)) {
    return { triggered: false };
  }

  const primaryReason = `Reserved TLD Detected — The domain uses a special-use extension (.${tld}) under RFC 2606 that cannot be registered or resolved on the public Internet.`;
  const mechanism = `TLD matches permanently reserved non-routable namespace (.${tld}).`;
  const securityImpact = `Cannot be verified via public DNS and cannot establish authenticated connections.`;

  return {
    triggered: true,
    tld,
    ruleId: 'reserved_special_tld',
    severity: 'review',
    tag: 'RESERVED TLD',
    title: 'Special-Use / Non-Routable Domain',
    primaryReason,
    mechanism,
    securityImpact
  };
}

/**
 * Standard rule evaluator interface conforming to Link Sentinel engine rules.
 *
 * @param {object} parsedContext
 * @returns {object} { rules, anomalies, specialTld }
 */
export function evaluateSpecialTldRule(parsedContext) {
  const { domainInfo, url } = parsedContext || {};
  const result = checkSpecialTld(domainInfo, url?.hostname);
  const rules = [];
  const anomalies = [];

  if (result.triggered) {
    rules.push({
      id: result.ruleId,
      ruleId: result.ruleId,
      name: result.title,
      title: result.title,
      severity: result.severity,
      reason: result.primaryReason,
      primaryReason: result.primaryReason,
      mechanism: result.mechanism,
      securityImpact: result.securityImpact
    });
    anomalies.push('reserved_special_tld');
  }

  return { rules, anomalies, specialTld: result };
}

export default {
  RESERVED_TLDS,
  SAFE_DOCUMENTATION_DOMAINS,
  isSafeDocumentationContext,
  checkSpecialTld,
  evaluateSpecialTldRule
};
