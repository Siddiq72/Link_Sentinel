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

import psl from 'psl';
import { parseInput } from './parse.js';
import { analyzeDomain, isIpv4, isIpv6 } from './domain.js';
import { evaluateSchemeRule } from './rules/schemeRule.js';
import { evaluateUserinfoRule, evaluateAuthorityRule } from './rules/authorityRule.js';
import { evaluateIpRule } from './rules/ipRule.js';
import { evaluateLookalikeRule } from './rules/lookalikeRule.js';
import { evaluateShortenerRule } from './rules/shortenerRule.js';
import { detectAndParsePayload } from './payloads/index.js';

export { parseInput } from './parse.js';
export { analyzeDomain, isIpv4, isIpv6 } from './domain.js';
export { evaluateSchemeRule } from './rules/schemeRule.js';
export { evaluateUserinfoRule, evaluateAuthorityRule } from './rules/authorityRule.js';
export { evaluateIpRule } from './rules/ipRule.js';
export { evaluateLookalikeRule } from './rules/lookalikeRule.js';
export { evaluateShortenerRule } from './rules/shortenerRule.js';
export { detectAndParsePayload } from './payloads/index.js';

/**
 * Analyzes a URL string synchronously for deceptive routing and structural signals.
 *
 * @param {string} input - Raw URL string entered by user.
 * @returns {object} Analysis result conforming to the Link Sentinel data contract.
 * @throws {Error} If input is invalid, empty, or unparseable.
 */
export function analyze(input) {
  // Input Clamping & Sanitization: Empty / Whitespace-only
  if (input === null || input === undefined || typeof input !== 'string') {
    throw new Error('Please enter a valid link. Please enter a link or scan a QR code to inspect.');
  }
  if (!input.trim()) {
    throw new Error('Please enter a valid link. Please enter a link or scan a QR code to inspect.');
  }

  // Global Safety-Net Wrapper
  try {
    // 1. String Length Ceiling: input.length > 2048
    if (input.length > 2048) {
      const primaryReason = "Oversized Input — Link length exceeds standard URL limits (2048 characters). Truncated to prevent regex resource exhaustion.";
      return {
        input: input.slice(0, 2048),
        verdict: 'review',
        tag: 'EXCESSIVE LENGTH',
        primaryReason,
        rules: [
          {
            id: 'excessive-length',
            name: 'Excessive Link Length',
            severity: 'review',
            reason: primaryReason
          }
        ],
        reasons: [
          {
            ruleId: 'excessive-length',
            severity: 'review',
            title: 'Excessive Link Length',
            mechanism: 'Input length exceeds 2048 character standard limit.',
            securityImpact: 'Excessively long links may trigger resource exhaustion or conceal malicious parameters.'
          }
        ],
        anomalies: ['excessive_length'],
        parts: {
          protocol: '',
          userinfo: '',
          host: '',
          registrableDomain: 'Oversized Link Payload',
          port: '',
          path: '',
          query: ''
        },
        passedRules: [],
        lookalikeDiff: null
      };
    }

    const trimmed = input.trim();

    // 2. Two Links Pasted Together (e.g. whitespace/newline separation containing multiple :// or schemes)
    if (/\s/.test(trimmed)) {
      const tokens = trimmed.split(/\s+/).filter(Boolean);
      const schemeTokens = tokens.filter((t) =>
        /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/|^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]/.test(t) || t.includes('://')
      );
      const protocolCount = (trimmed.match(/:\/\//g) || []).length;

      if (schemeTokens.length >= 2 || protocolCount >= 2) {
        const primaryReason = "Multiple destinations detected — Link Sentinel inspects one link at a time. Please test links individually.";
        return {
          input: trimmed,
          verdict: 'review',
          tag: 'MULTIPLE TARGETS',
          primaryReason,
          rules: [
            {
              id: 'multiple-targets',
              name: 'Multiple Destinations Detected',
              severity: 'review',
              reason: primaryReason
            }
          ],
          reasons: [
            {
              ruleId: 'multiple-targets',
              severity: 'review',
              title: 'Multiple Targets Pasted',
              mechanism: 'Input contains multiple whitespace- or newline-separated destination links.',
              securityImpact: 'Compound input cannot be attributed to a single authority origin. Inspect each link separately.'
            }
          ],
          anomalies: ['multiple_targets'],
          parts: {
            protocol: '',
            userinfo: '',
            host: '',
            registrableDomain: 'Multiple Destination Targets',
            port: '',
            path: '',
            query: ''
          },
          passedRules: [],
          lookalikeDiff: null
        };
      }
    }

    // 3. Non-URL Payload Screening (UPI, Wi-Fi, Natural Language Plain Text)
    const nonUrlPayload = detectAndParsePayload(input);
    if (nonUrlPayload) {
      return {
        input: trimmed,
        verdict: nonUrlPayload.verdict,
        payloadType: nonUrlPayload.type,
        data: nonUrlPayload.data,
        primaryReason: nonUrlPayload.primaryReason,
        tag: nonUrlPayload.tag,
        rules: nonUrlPayload.rules || [],
        reasons: nonUrlPayload.rules || [],
        passedRules: nonUrlPayload.passedRules || [],
        anomalies: nonUrlPayload.anomalies || [],
        parts: nonUrlPayload.parts || {
          protocol: '',
          userinfo: '',
          host: '',
          registrableDomain: '',
          port: '',
          path: '',
          query: ''
        },
        lookalikeDiff: null
      };
    }

    // 4. Emoji / Random Gibberish (e.g. 🚀🔥🦄 or sdkjfhskdjhf without TLD/scheme)
    const hasHierarchicalScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(trimmed);
    const isKnownScheme = /^(javascript|vbscript|data|mailto|tel|sms|file|upi|wifi|blob):/i.test(trimmed);

    if (!hasHierarchicalScheme && !isKnownScheme) {
      const candidateHost = trimmed.split(/[/?#]/)[0].toLowerCase().replace(/\.+$/, '');
      const isIpHost = isIpv4(candidateHost) || isIpv6(candidateHost) || candidateHost === 'localhost';
      let hasRecognizedTld = false;

      if (candidateHost.includes('.')) {
        if (
          candidateHost.endsWith('.example') ||
          candidateHost.endsWith('.localhost') ||
          candidateHost.endsWith('.test') ||
          candidateHost.endsWith('.local')
        ) {
          hasRecognizedTld = true;
        } else {
          const parsed = psl.parse(candidateHost);
          if (parsed && parsed.listed) {
            hasRecognizedTld = true;
          }
        }
      }

      if (!isIpHost && !hasRecognizedTld) {
        const primaryReason = "Unrecognized structure — Input does not match a valid URL, network intent, or recognized barcode format.";
        return {
          input: trimmed,
          verdict: 'review',
          tag: 'UNRECOGNIZED INPUT',
          primaryReason,
          rules: [
            {
              id: 'unrecognized-input',
              name: 'Unrecognized Structure',
              severity: 'review',
              reason: primaryReason
            }
          ],
          reasons: [
            {
              ruleId: 'unrecognized-input',
              severity: 'review',
              title: 'Unrecognized Input Structure',
              mechanism: 'Input does not match a valid URL, network intent, or recognized barcode format.',
              securityImpact: 'Input cannot be resolved to any authenticated network authority or offline verified institutional domain.'
            }
          ],
          anomalies: ['unrecognized_input'],
          parts: {
            protocol: '',
            userinfo: '',
            host: candidateHost || '',
            registrableDomain: 'Unrecognized Input',
            port: '',
            path: '',
            query: ''
          },
          passedRules: [],
          lookalikeDiff: null
        };
      }
    }

    // 5. URL Parsing & Preprocessing
    let parsedContext;
    try {
      parsedContext = parseInput(input);
    } catch (err) {
      if (err.isMalformed) {
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
          passedRules: [],
          lookalikeDiff: null
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

    // 2. Authority & Userinfo rule (includes %40 and %2540 defense)
    const userinfoRes = evaluateUserinfoRule(context);
    userinfoRes.rules.forEach((r) => rules.push(r));
    userinfoRes.anomalies.forEach((a) => anomaliesSet.add(a));

    // 3. IP rule
    const ipRes = evaluateIpRule(context);
    ipRes.rules.forEach((r) => rules.push(r));
    ipRes.anomalies.forEach((a) => anomaliesSet.add(a));

    // 4. Lookalike & Non-Latin rule
    const lookalikeRes = evaluateLookalikeRule(context);
    lookalikeRes.rules.forEach((r) => rules.push(r));
    lookalikeRes.anomalies.forEach((a) => anomaliesSet.add(a));
    const lookalikeDiff = lookalikeRes?.diff || null;

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

    // Dedicated Banner Tag and Primary Reason assignments
    let tag;
    let primaryReason;

    if (anomaliesSet.has('executable_data') || rules.some((r) => r.id === 'dangerous-scheme-data-html')) {
      tag = 'EXECUTABLE DATA';
      primaryReason = "Data URI Scheme — Encodes inline executable HTML or script content directly inside the link.";
    } else if (anomaliesSet.has('non_latin_script') || rules.some((r) => r.id === 'non-latin-script')) {
      tag = 'NON-LATIN SCRIPT';
      primaryReason = "Internationalized Domain Name — Uses full non-Latin script. Cannot verify authority against Latin-alphabet targets offline.";
    }

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

    const result = {
      input: rawInput,
      verdict,
      parts,
      anomalies: Array.from(anomaliesSet),
      rules,
      passedRules,
      lookalikeDiff: lookalikeDiff || null
    };

    if (tag) result.tag = tag;
    if (primaryReason) result.primaryReason = primaryReason;

    return result;
  } catch (err) {
    console.error("Link Sentinel parsing safety net caught exception:", err);
    return {
      verdict: 'review',
      tag: 'REVIEW',
      payloadType: 'ERROR',
      primaryReason: "Malformed Syntax — Unable to safely deconstruct destination authority offline.",
      reasons: [{
        ruleId: 'parser_safety_net',
        severity: 'review',
        title: 'Unparseable Input Structure',
        mechanism: 'Link triggered an unhandled parser edge case.',
        securityImpact: 'Proceed with caution. Malformed links are frequently crafted to exploit parser differential vulnerabilities.'
      }],
      parts: {
        protocol: '',
        userinfo: '',
        host: '',
        registrableDomain: 'Malformed Link Structure',
        port: '',
        path: '',
        query: ''
      },
      rules: [{
        id: 'parser_safety_net',
        name: 'Unparseable Input Structure',
        severity: 'review',
        reason: 'Link triggered an unhandled parser edge case.',
        mechanism: 'Link triggered an unhandled parser edge case.',
        securityImpact: 'Proceed with caution. Malformed links are frequently crafted to exploit parser differential vulnerabilities.'
      }],
      passedRules: []
    };
  }
}

export default analyze;
