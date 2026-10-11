/**
 * Evaluates whether a domain is a known URL shortening / redirection service.
 * Flags:
 * - Matches in KNOWN_SHORTENERS as "review"
 */

import { KNOWN_SHORTENERS } from '../data/shorteners.js';

export function evaluateShortenerRule(parsedContext) {
  const { url, domainInfo } = parsedContext;
  const domain = (domainInfo?.domain || url.hostname || '').toLowerCase();
  const hostname = (domainInfo?.hostname || url.hostname || '').toLowerCase();

  const rules = [];
  const anomalies = [];

  if (KNOWN_SHORTENERS.has(domain) || KNOWN_SHORTENERS.has(hostname)) {
    rules.push({
      id: 'destination-obfuscation',
      name: 'Destination Obfuscation',
      severity: 'review',
      reason: 'Shortened link: the real destination is hidden and cannot be checked offline.'
    });
    anomalies.push('url_shortener');
  }

  return { rules, anomalies };
}

export default evaluateShortenerRule;
