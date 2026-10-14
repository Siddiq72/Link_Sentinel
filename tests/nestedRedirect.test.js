import { describe, it, expect } from 'vitest';
import {
  evaluateNestedRedirects,
  evaluateNestedRedirectRule,
  REDIRECT_PARAM_KEYS
} from '../src/engine/rules/nestedRedirectRule.js';
import { analyze } from '../src/engine/index.js';

describe('1. Single Embedded Redirect Parameter (OPEN_REDIRECT_PARAM)', () => {
  it('triggers Review needed / OPEN_REDIRECT_PARAM for a single redirect parameter', () => {
    const url = 'https://portal.example.com/login?redirect=https://destination.example.com/dashboard';
    const result = evaluateNestedRedirects(url);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBe(1);
    expect(result.severity).toBe('Review needed');
    expect(result.category).toBe('OPEN_REDIRECT_PARAM');
    expect(result.scoreImpact).toBe(15);
    expect(result.explanation).toBe(
      'Detected an embedded redirect parameter pointing to an external destination.'
    );
    expect(result.chain).toEqual(['https://destination.example.com/dashboard']);
  });

  it('detects embedded forwarding targets across various recognized parameter keys', () => {
    const targetKeys = [
      'url',
      'dest',
      'destination',
      'target',
      'next',
      'goto',
      'return',
      'return_url',
      'forward',
      'r',
      'checkout_url'
    ];

    for (const key of targetKeys) {
      const url = `https://service.example.org/auth?${key}=https://auth-target.com/callback`;
      const result = evaluateNestedRedirects(url);

      expect(result.triggered).toBe(true);
      expect(result.hops).toBe(1);
      expect(result.category).toBe('OPEN_REDIRECT_PARAM');
      expect(result.chain[0]).toBe('https://auth-target.com/callback');
    }
  });

  it('unpacks single and double percent-encoded URL values', () => {
    // Single encoded
    const singleEncoded = 'https://example.com/nav?dest=https%3A%2F%2Fexternal.com%2Fwelcome';
    const singleRes = evaluateNestedRedirects(singleEncoded);
    expect(singleRes.triggered).toBe(true);
    expect(singleRes.chain[0]).toBe('https://external.com/welcome');

    // Double encoded
    const doubleEncoded = 'https://example.com/nav?dest=https%253A%252F%252Fexternal.com%252Fwelcome';
    const doubleRes = evaluateNestedRedirects(doubleEncoded);
    expect(doubleRes.triggered).toBe(true);
    expect(doubleRes.chain[0]).toBe('https://external.com/welcome');
  });

  it('detects embedded target in hash fragment query string', () => {
    const hashUrl = 'https://spa.example.com/#/portal?dest=https://external.example.com';
    const result = evaluateNestedRedirects(hashUrl);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBe(1);
    expect(result.chain[0]).toBe('https://external.example.com');
  });
});

describe('2. Multi-Hop Nested Redirect Chains (MULTIPLE_REDIRECT_CHAIN)', () => {
  it('triggers Suspicious / MULTIPLE_REDIRECT_CHAIN for two nested redirect hops', () => {
    const url = 'https://a.com?url=https://b.com?dest=https://c.com';
    const result = evaluateNestedRedirects(url);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBe(2);
    expect(result.severity).toBe('Suspicious');
    expect(result.category).toBe('MULTIPLE_REDIRECT_CHAIN');
    expect(result.scoreImpact).toBe(35);
    expect(result.explanation).toBe(
      'Detected a multi-hop nested redirect chain embedded in URL parameters. Attackers use layered parameter bouncing to bypass standard link filters.'
    );
    expect(result.chain).toEqual([
      'https://b.com?dest=https://c.com',
      'https://c.com'
    ]);
  });

  it('handles multi-hop chains with 3 or more layers', () => {
    const threeHop = 'https://first.com?redirect=https://second.com?next=https://third.com?goto=https://final.com';
    const result = evaluateNestedRedirects(threeHop);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBe(3);
    expect(result.severity).toBe('Suspicious');
    expect(result.category).toBe('MULTIPLE_REDIRECT_CHAIN');
    expect(result.scoreImpact).toBe(35);
    expect(result.chain.length).toBe(3);
    expect(result.chain[2]).toBe('https://final.com');
  });

  it('traverses nested percent-encoded bounce targets', () => {
    const encodedChain = 'https://a.com?url=https%3A%2F%2Fb.com%3Fdest%3Dhttps%253A%252F%252Fc.com';
    const result = evaluateNestedRedirects(encodedChain);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBe(2);
    expect(result.severity).toBe('Suspicious');
    expect(result.category).toBe('MULTIPLE_REDIRECT_CHAIN');
  });

  it('safely bounds traversal to 6 hops to prevent denial-of-service', () => {
    // Generate an 8-hop deep simulated chain
    let deepChain = 'https://hop8.com/end';
    for (let i = 7; i >= 1; i--) {
      deepChain = `https://hop${i}.com?dest=${encodeURIComponent(deepChain)}`;
    }

    const result = evaluateNestedRedirects(deepChain);
    expect(result.triggered).toBe(true);
    expect(result.hops).toBeLessThanOrEqual(6);
    expect(result.severity).toBe('Suspicious');
  });

  it('breaks cycles to avoid infinite loops on circular self-redirects', () => {
    const circular = 'https://a.com?url=https://a.com?url=https://a.com';
    const result = evaluateNestedRedirects(circular);

    expect(result.triggered).toBe(true);
    expect(result.hops).toBeLessThanOrEqual(6);
  });
});

describe('3. Clean Links & Benign Query Parameters (Negative Cases)', () => {
  it('returns triggered: false for clean institutional links without parameters', () => {
    const result = evaluateNestedRedirects('https://campus.example/notices/lab-3');
    expect(result.triggered).toBe(false);
    expect(result.hops).toBe(0);
    expect(result.chain).toEqual([]);
  });

  it('returns triggered: false for clean links with standard non-redirect query parameters', () => {
    const cleanWithParams = 'https://example.com/search?q=cybersecurity&sort=recent&page=2';
    const result = evaluateNestedRedirects(cleanWithParams);
    expect(result.triggered).toBe(false);
    expect(result.hops).toBe(0);
  });

  it('ignores relative path redirects that do not point to external http/https authorities', () => {
    const relativeRedirect = 'https://example.com/login?redirect=/user/dashboard';
    const result = evaluateNestedRedirects(relativeRedirect);
    expect(result.triggered).toBe(false);
  });

  it('ignores email addresses in benign query parameters', () => {
    const contactParam = 'https://portal.campus.example/forms?contact=lab@campus.example';
    const result = evaluateNestedRedirects(contactParam);
    expect(result.triggered).toBe(false);
  });
});

describe('4. Error Handling & Malformed Input Safety', () => {
  it('handles empty, null, and non-string inputs safely without exceptions', () => {
    expect(evaluateNestedRedirects('')).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects('   ')).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects(null)).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects(undefined)).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects(12345)).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects({})).toEqual({ triggered: false, hops: 0, chain: [] });
  });

  it('handles malformed URL syntax safely', () => {
    expect(evaluateNestedRedirects('https://::')).toEqual({ triggered: false, hops: 0, chain: [] });
    expect(evaluateNestedRedirects('not_a_valid_url')).toEqual({ triggered: false, hops: 0, chain: [] });
  });

  it('handles corrupted percent-encoding sequences safely', () => {
    const corruptedEncoding = 'https://example.com?url=%E0%A4%A';
    const result = evaluateNestedRedirects(corruptedEncoding);
    expect(result.triggered).toBe(false);
  });
});

describe('5. Full Link Sentinel Detection Pipeline Integration', () => {
  it('integrates single redirect parameter into analyze() resulting in review verdict', () => {
    const res = analyze('https://login.example.com/auth?redirect=https://unknown-destination.com');

    expect(res.verdict).toBe('review');
    expect(res.tag).toBe('OPEN REDIRECT');
    expect(res.anomalies).toContain('open_redirect_param');
    expect(res.rules.some((r) => r.id === 'open-redirect-parameter')).toBe(true);
    expect(res.nestedRedirects.hops).toBe(1);
    expect(res.scoreImpact).toBe(15);
  });

  it('integrates multi-hop redirect chain into analyze() resulting in suspicious verdict', () => {
    const res = analyze('https://bounce1.com?url=https://bounce2.com?dest=https://final-destination.com');

    expect(res.verdict).toBe('suspicious');
    expect(res.tag).toBe('REDIRECT CHAIN');
    expect(res.anomalies).toContain('multiple_redirect_chain');
    expect(res.rules.some((r) => r.id === 'nested-redirect-chain')).toBe(true);
    expect(res.nestedRedirects.hops).toBe(2);
    expect(res.scoreImpact).toBe(35);
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('clean links continue to receive safe verdict and passed rule attribution', () => {
    const res = analyze('https://campus.example/notices/lab-3');

    expect(res.verdict).toBe('safe');
    expect(res.anomalies).not.toContain('multiple_redirect_chain');
    expect(res.anomalies).not.toContain('open_redirect_param');
    expect(res.passedRules).toContain('Zero nested redirect parameters or bounce chains');
  });
});
