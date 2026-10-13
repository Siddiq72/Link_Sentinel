/**
 * LINK SENTINEL - SYNCHRONOUS DETERMINISTIC THREAT DETECTION ENGINE
 * 
 * Client-side, zero-network threat analysis and defensive URL parser.
 * Conforms strictly to the Link Sentinel data contract:
 * {
 *   input: string,
 *   verdict: "safe" | "review" | "suspicious",
 *   parts: { protocol, userinfo, host, registrableDomain, port, path, query },
 *   anomalies: string[],
 *   rules: [{ id, name, severity, reason }],
 *   passedRules?: string[]
 * }
 */

import { parseInput } from './parse.js';
import { analyzeDomain } from './domain.js';
import { evaluateSchemeRule } from './rules/schemeRule.js';
import { evaluateUserinfoRule } from './rules/userinfoRule.js';
import { evaluateIpRule } from './rules/ipRule.js';
import { evaluateLookalikeRule } from './rules/lookalikeRule.js';
import { evaluateShortenerRule } from './rules/shortenerRule.js';

export { parseInput } from './parse.js';
export { analyzeDomain } from './domain.js';
export { evaluateSchemeRule } from './rules/schemeRule.js';
export { evaluateUserinfoRule } from './rules/userinfoRule.js';
export { evaluateIpRule } from './rules/ipRule.js';
export { evaluateLookalikeRule } from './rules/lookalikeRule.js';
export { evaluateShortenerRule } from './rules/shortenerRule.js';

/**
 * Analyzes a URL string synchronously for deceptive routing and structural signals.
 *
 * @param {string} input - Raw URL string entered by user.
 * @returns {object} Analysis result conforming to the Link Sentinel data contract.
 * @throws {Error} If input is invalid, empty, or unparseable.
 */
export function analyze(input) {
  if (input === null || input === undefined || typeof input !== 'string') {
    throw new Error('Please enter a valid link.');
  }
  if (!input.trim()) {
    throw new Error('Please enter a valid link.');
  }

  let parsedContext;
  try {
    parsedContext = parseInput(input);
  } catch (err) {
    if (err.isMalformed) {
      const trimmed = input.trim();
      const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(\/\/)?/);
      const protocol = schemeMatch ? schemeMatch[0] : 'https://';
      const remainder = schemeMatch ? trimmed.slice(schemeMatch[0].length) : trimmed;
      const host = remainder.split(/[/?#]/)[0] || 'malformed-authority';

      return {
        input: trimmed,
        verdict: 'suspicious',
        parts: {
          protocol,
          userinfo: '',
          host,
          registrableDomain: 'Malformed Link Structure',
          port: '',
          path: remainder.includes('/') ? '/' + remainder.slice(remainder.indexOf('/') + 1) : '',
          query: remainder.includes('?') ? '?' + remainder.split('?')[1] : ''
        },
        anomalies: ['malformed_uri_syntax'],
        rules: [
          {
            id: 'malformed-link',
            name: 'Malformed Link Syntax',
            severity: 'suspicious',
            reason: 'Flagged: URI structure violates RFC/WHATWG specifications (e.g. invalid IPv6 brackets, corrupt port number, or illegal authority syntax).'
          }
        ],
        passedRules: []
      };
    }
    throw err;
  }

  const { url, rawInput, hasBidi, hasBackslash, hasZeroWidth } = parsedContext;

  const domainInfo = analyzeDomain(url.hostname);
  const context = {
    ...parsedContext,
    domainInfo
  };

  const rules = [];
  const anomaliesSet = new Set();

  // Flag input sanitization anomalies
  if (hasBidi) {
    rules.push({
      id: 'bidi-override',
      name: 'Bidirectional Text Override',
      severity: 'suspicious',
      reason: 'Flagged: contains Unicode bidirectional override characters used to visually reverse link text.'
    });
    anomaliesSet.add('bidi_override');
  }

  if (hasBackslash) {
    rules.push({
      id: 'backslash-obfuscation',
      name: 'Backslash Delimiter Discrepancy',
      severity: 'suspicious',
      reason: 'Flagged: contains backslash characters intended to exploit browser parser discrepancies.'
    });
    anomaliesSet.add('backslash_obfuscation');
  }

  if (hasZeroWidth) {
    rules.push({
      id: 'zero-width-character',
      name: 'Zero-Width Padding',
      severity: 'suspicious',
      reason: 'Flagged: contains invisible zero-width characters used to evade string filters.'
    });
    anomaliesSet.add('zero_width_character');
  }

  // 1. Scheme rule
  const schemeRes = evaluateSchemeRule(context);
  schemeRes.rules.forEach((r) => rules.push(r));
  schemeRes.anomalies.forEach((a) => anomaliesSet.add(a));

  // 2. Userinfo rule
  const userinfoRes = evaluateUserinfoRule(context);
  userinfoRes.rules.forEach((r) => rules.push(r));
  userinfoRes.anomalies.forEach((a) => anomaliesSet.add(a));

  // 3. IP rule
  const ipRes = evaluateIpRule(context);
  ipRes.rules.forEach((r) => rules.push(r));
  ipRes.anomalies.forEach((a) => anomaliesSet.add(a));

  // 4. Lookalike rule
  const lookalikeRes = evaluateLookalikeRule(context);
  lookalikeRes.rules.forEach((r) => rules.push(r));
  lookalikeRes.anomalies.forEach((a) => anomaliesSet.add(a));

  // 5. Shortener rule
  const shortenerRes = evaluateShortenerRule(context);
  shortenerRes.rules.forEach((r) => rules.push(r));
  shortenerRes.anomalies.forEach((a) => anomaliesSet.add(a));

  // Aggregation hierarchy: "suspicious" > "review" > "safe"
  let verdict = 'safe';
  const hasSuspicious = rules.some((r) => r.severity === 'suspicious');
  const hasReview = rules.some((r) => r.severity === 'review');

  if (hasSuspicious) {
    verdict = 'suspicious';
  } else if (hasReview) {
    verdict = 'review';
  } else {
    verdict = 'safe';
  }

  // Format parts according to Link Sentinel UI anatomy breakdown
  const protocolRaw = url.protocol || '';
  const isSpecialScheme = /^(javascript|vbscript|data|mailto|tel|sms):/i.test(protocolRaw);
  const protocol = protocolRaw ? (isSpecialScheme ? protocolRaw : `${protocolRaw}//`) : '';

  const userinfo = url.username
    ? `${url.username}${url.password ? `:${url.password}` : ''}@`
    : '';

  const host = domainInfo.unicodeHostname || url.hostname || '';
  const registrableDomain = domainInfo.registrableDomain || host;
  const port = url.port ? `:${url.port}` : '';
  const path = url.pathname || '';
  const query = url.search || '';

  const parts = {
    protocol,
    userinfo,
    host,
    registrableDomain,
    port,
    path,
    query
  };

  // Provide informative default rule for safe verdicts if none fired
  if (verdict === 'safe' && rules.length === 0) {
    rules.push({
      id: 'standard-route',
      name: 'Standard Institutional Route',
      severity: 'note',
      reason: 'This link uses https. No deception signals were found in its structure.'
    });
  }

  // Update http note text
  for (const r of rules) {
    if (r.id === 'insecure-scheme') {
      r.reason = 'This link uses http, not https, so data sent to it is not encrypted.';
    }
  }

  // Passed rules breakdown
  const passedRules = [];
  if (!userinfo) {
    passedRules.push('No unescaped authority credential spoofing');
  }
  if (!anomaliesSet.has('homoglyph_cyrillic') && !anomaliesSet.has('homoglyph_greek')) {
    passedRules.push('Zero Unicode or Cyrillic homoglyph characters');
  }
  if (protocolRaw === 'https:') {
    passedRules.push('Transport Layer Security declared (HTTPS)');
  }
  if (!url.port || url.port === '443' || url.port === '80') {
    passedRules.push('Standard default port utilized');
  } else {
    passedRules.push(`Explicit non-standard port ${url.port} recognized`);
  }
  if (!anomaliesSet.has('url_shortener')) {
    passedRules.push('Unobfuscated direct navigation route');
  }

  return {
    input: rawInput,
    verdict,
    parts,
    anomalies: Array.from(anomaliesSet),
    rules,
    passedRules
  };
}

export default analyze;
