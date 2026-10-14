/**
 * NESTED REDIRECT CHAIN DETECTION HEURISTIC
 *
 * Offline-first, client-side analysis of URL search and hash parameters
 * to detect embedded forwarding targets and layered bounce chains.
 *
 * Security & Anti-Evasion Capabilities:
 * 1. ZERO NETWORK TRAFFIC: Traverses parameter structures completely on-device.
 * 2. RECURSIVE HOP DETECTION: Iteratively resolves nested destination parameters
 *    up to a maximum depth ceiling of 6 hops to prevent infinite-loop DoS.
 * 3. MULTI-LAYER UNPACKING: Handles nested single and double percent-encoded URLs.
 * 4. FAIL-SAFE: Gracefully handles truncated, malformed, or hostile syntax without throwing.
 */

export const REDIRECT_PARAM_KEYS = Object.freeze([
  'redirect',
  'redirect_to',
  'redirect_url',
  'return',
  'return_url',
  'returnurl',
  'next',
  'dest',
  'destination',
  'target',
  'url',
  'goto',
  'checkout_url',
  'forward',
  'out',
  'view',
  'r'
]);

const REDIRECT_PARAM_KEYS_SET = new Set(REDIRECT_PARAM_KEYS);

/**
 * Safely decodes a URI component, unwrapping up to 3 layers of encoding
 * without throwing on malformed percent sequences.
 *
 * @param {string} val
 * @returns {string|null} Unpacked URL if starting with http:// or https://, null otherwise.
 */
function extractCandidateUrl(val) {
  if (typeof val !== 'string' || !val.trim()) {
    return null;
  }

  let decoded = val.trim();

  // Iteratively unwrap percent-encoding up to 3 times
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next.trim();
    } catch {
      break;
    }
  }

  // Strictly target external web schemes (http:// and https://)
  if (/^https?:\/\//i.test(decoded)) {
    return decoded;
  }

  return null;
}

/**
 * Parses query parameters from both the search string and hash fragment of a URL string.
 *
 * @param {string} urlStr
 * @returns {URLSearchParams[]}
 */
function parseUrlParameterSources(urlStr) {
  const sources = [];

  try {
    const parsed = new URL(urlStr);
    if (parsed.searchParams) {
      sources.push(parsed.searchParams);
    }
  } catch {
    // If lacks protocol, try prepending https://
    try {
      const parsed = new URL('https://' + urlStr.replace(/^\/+/, ''));
      if (parsed.searchParams) {
        sources.push(parsed.searchParams);
      }
    } catch {
      // Manual query string extraction fallback
      const qIdx = urlStr.indexOf('?');
      if (qIdx !== -1) {
        const queryPart = urlStr.slice(qIdx + 1).split('#')[0];
        try {
          sources.push(new URLSearchParams(queryPart));
        } catch {
          // ignore
        }
      }
    }
  }

  // Inspect hash fragment for secondary query parameters (e.g., #/auth?url=https://...)
  const hashIdx = urlStr.indexOf('#');
  if (hashIdx !== -1) {
    const hashPart = urlStr.slice(hashIdx + 1);
    const hashQIdx = hashPart.indexOf('?');
    if (hashQIdx !== -1) {
      try {
        sources.push(new URLSearchParams(hashPart.slice(hashQIdx + 1)));
      } catch {
        // ignore
      }
    }
  }

  return sources;
}

/**
 * Evaluates nested redirect parameter chains completely offline.
 *
 * @param {string|object} urlInput - Raw URL string, parsed object, or URL instance.
 * @returns {{
 *   triggered: boolean,
 *   hops: number,
 *   chain: string[],
 *   severity?: 'Suspicious' | 'Review needed',
 *   category?: 'MULTIPLE_REDIRECT_CHAIN' | 'OPEN_REDIRECT_PARAM',
 *   scoreImpact?: number,
 *   explanation?: string,
 *   error?: string
 * }}
 */
export function evaluateNestedRedirects(urlInput) {
  try {
    if (!urlInput) {
      return { triggered: false, hops: 0, chain: [] };
    }

    let initialString = '';
    if (typeof urlInput === 'string') {
      initialString = urlInput.trim();
    } else if (urlInput instanceof URL) {
      initialString = urlInput.href;
    } else if (typeof urlInput === 'object') {
      initialString = urlInput.input || urlInput.raw || urlInput.url?.href || '';
    }

    if (!initialString || typeof initialString !== 'string') {
      return { triggered: false, hops: 0, chain: [] };
    }

    let current = initialString.trim();
    const chain = [];
    const visited = new Set();
    const maxDepth = 6;

    while (chain.length < maxDepth) {
      const sources = parseUrlParameterSources(current);
      let nextCandidate = null;

      for (const params of sources) {
        for (const [key, val] of params.entries()) {
          if (REDIRECT_PARAM_KEYS_SET.has(key.toLowerCase())) {
            const candidate = extractCandidateUrl(val);
            if (candidate) {
              nextCandidate = candidate;
              break;
            }
          }
        }
        if (nextCandidate) break;
      }

      if (!nextCandidate) {
        break;
      }

      // Cycle / infinite-loop defense
      const normalizedCandidate = nextCandidate.toLowerCase();
      if (visited.has(normalizedCandidate)) {
        break;
      }

      visited.add(normalizedCandidate);
      chain.push(nextCandidate);
      current = nextCandidate;
    }

    const hops = chain.length;

    if (hops >= 2) {
      return {
        triggered: true,
        hops,
        chain,
        severity: 'Suspicious',
        category: 'MULTIPLE_REDIRECT_CHAIN',
        scoreImpact: 35,
        explanation:
          'Detected a multi-hop nested redirect chain embedded in URL parameters. Attackers use layered parameter bouncing to bypass standard link filters.'
      };
    }

    if (hops === 1) {
      return {
        triggered: true,
        hops: 1,
        chain,
        severity: 'Review needed',
        category: 'OPEN_REDIRECT_PARAM',
        scoreImpact: 15,
        explanation: 'Detected an embedded redirect parameter pointing to an external destination.'
      };
    }

    return {
      triggered: false,
      hops: 0,
      chain: []
    };
  } catch (err) {
    return {
      triggered: false,
      hops: 0,
      chain: [],
      error: err?.message || 'Redirect parser failed safely'
    };
  }
}

/**
 * Standard rule evaluator conforming to the Link Sentinel engine interface.
 *
 * @param {object} parsedContext
 * @returns {object} { rules, anomalies, nestedRedirects }
 */
export function evaluateNestedRedirectRule(parsedContext) {
  const urlStr =
    parsedContext?.rawInput ||
    parsedContext?.input ||
    parsedContext?.url?.href ||
    (typeof parsedContext === 'string' ? parsedContext : '');

  const result = evaluateNestedRedirects(urlStr);
  const rules = [];
  const anomalies = [];

  if (result.triggered) {
    const isSuspicious = result.severity.toLowerCase().startsWith('suspicious');
    const ruleSeverity = isSuspicious ? 'suspicious' : 'review';
    const ruleId =
      result.category === 'MULTIPLE_REDIRECT_CHAIN'
        ? 'nested-redirect-chain'
        : 'open-redirect-parameter';
    const ruleTitle =
      result.category === 'MULTIPLE_REDIRECT_CHAIN'
        ? 'Nested Redirect Chain'
        : 'Embedded Open Redirect Parameter';

    rules.push({
      id: ruleId,
      ruleId,
      name: ruleTitle,
      title: ruleTitle,
      severity: ruleSeverity,
      category: result.category,
      hops: result.hops,
      chain: result.chain,
      scoreImpact: result.scoreImpact,
      reason: result.explanation,
      primaryReason: result.explanation,
      explanation: result.explanation,
      mechanism: `URL contains embedded redirect target${result.hops > 1 ? ` across ${result.hops} hops` : ''}.`,
      securityImpact: result.explanation
    });

    if (result.category === 'MULTIPLE_REDIRECT_CHAIN') {
      anomalies.push('multiple_redirect_chain');
    } else {
      anomalies.push('open_redirect_param');
    }
  }

  return { rules, anomalies, nestedRedirects: result };
}

export default {
  REDIRECT_PARAM_KEYS,
  evaluateNestedRedirects,
  evaluateNestedRedirectRule
};
