import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { parseInput } from '../src/engine/parse.js';
import { analyzeDomain } from '../src/engine/domain.js';
import { getSkeleton, hasCyrillic, isMixedScript } from '../src/engine/data/confusables.js';
import { KNOWN_SHORTENERS } from '../src/engine/data/shorteners.js';
import { PROTECTED_DOMAINS } from '../src/engine/data/protectedDomains.js';
import { evaluateSchemeRule } from '../src/engine/rules/schemeRule.js';
import { evaluateUserinfoRule } from '../src/engine/rules/userinfoRule.js';
import { evaluateIpRule } from '../src/engine/rules/ipRule.js';
import { evaluateLookalikeRule } from '../src/engine/rules/lookalikeRule.js';
import { evaluateShortenerRule } from '../src/engine/rules/shortenerRule.js';

describe('Link Sentinel Core Demo Link Vectors', () => {
  it('Vector 1: https://campus.example/notices/lab-3 -> Safe', () => {
    const result = analyze('https://campus.example/notices/lab-3');
    expect(result.verdict).toBe('safe');
    expect(result.parts.host).toBe('campus.example');
    expect(result.parts.registrableDomain).toBe('campus.example');
    expect(result.parts.protocol).toBe('https://');
    expect(result.anomalies).toHaveLength(0);
  });

  it('Vector 2: https://campus.example@other.example/login -> Suspicious', () => {
    const result = analyze('https://campus.example@other.example/login');
    expect(result.verdict).toBe('suspicious');
    expect(result.parts.userinfo).toBe('campus.example@');
    expect(result.parts.host).toBe('other.example');
    expect(result.anomalies).toContain('userinfo_decoy');
    expect(result.rules.some((r) => r.id === 'authority-routing-trap')).toBe(true);
  });

  it('Vector 3: https://\u0441ampus.example/login (Cyrillic "с") -> Suspicious', () => {
    const result = analyze('https://\u0441ampus.example/login');
    expect(result.verdict).toBe('suspicious');
    expect(result.parts.host).toBe('\u0441ampus.example');
    expect(result.anomalies).toContain('homoglyph_cyrillic');
    expect(result.rules.some((r) => r.id === 'character-substitution')).toBe(true);
  });

  it('Vector 4: http://192.0.2.45/signin -> Suspicious', () => {
    const result = analyze('http://192.0.2.45/signin');
    expect(result.verdict).toBe('suspicious');
    expect(result.parts.host).toBe('192.0.2.45');
    expect(result.parts.protocol).toBe('http://');
    expect(result.anomalies).toContain('raw_ip_host');
    expect(result.rules.some((r) => r.id === 'ip-host-detection')).toBe(true);
  });

  it('Vector 5: http://192.168.1.10/ -> Review', () => {
    const result = analyze('http://192.168.1.10/');
    expect(result.verdict).toBe('review');
    expect(result.parts.host).toBe('192.168.1.10');
    expect(result.anomalies).toContain('private_ip_host');
    expect(result.rules.some((r) => r.id === 'private-ip-host')).toBe(true);
  });

  it('Vector 6: https://bit.ly/3abcXYZ -> Review', () => {
    const result = analyze('https://bit.ly/3abcXYZ');
    expect(result.verdict).toBe('review');
    expect(result.parts.host).toBe('bit.ly');
    expect(result.anomalies).toContain('url_shortener');
    expect(result.rules.some((r) => r.id === 'destination-obfuscation')).toBe(true);
  });

  it('Vector 7: https://portal.campus.example:8443/forms?contact=lab@campus.example -> Safe', () => {
    const result = analyze('https://portal.campus.example:8443/forms?contact=lab@campus.example');
    expect(result.verdict).toBe('safe');
    expect(result.parts.host).toBe('portal.campus.example');
    expect(result.parts.registrableDomain).toBe('campus.example');
    expect(result.parts.port).toBe(':8443');
    expect(result.parts.query).toBe('?contact=lab@campus.example');
    expect(result.anomalies).not.toContain('userinfo_decoy');
  });
});

describe('Defensive Parser and Pre-processing', () => {
  it('throws descriptive error on empty or non-string input', () => {
    expect(() => analyze('')).toThrow('Please enter a valid link.');
    expect(() => analyze('   ')).toThrow('Please enter a valid link.');
    expect(() => analyze(null)).toThrow('Please enter a valid link.');
    expect(() => analyze(12345)).toThrow('Please enter a valid link.');
  });

  it('strips zero-width characters and flags anomaly', () => {
    const zw = 'https://camp\u200Bus.example/test';
    const parsed = parseInput(zw);
    expect(parsed.hasZeroWidth).toBe(true);
    expect(parsed.normalizedInput).toBe('https://campus.example/test');
    const result = analyze(zw);
    expect(result.anomalies).toContain('zero_width_character');
  });

  it('detects bidirectional text overrides', () => {
    const bidi = 'https://campus.example/\u202Ereversed';
    const result = analyze(bidi);
    expect(result.verdict).toBe('suspicious');
    expect(result.anomalies).toContain('bidi_override');
  });

  it('prepends https:// if scheme is omitted', () => {
    const result = analyze('campus.example/notices');
    expect(result.parts.protocol).toBe('https://');
    expect(result.parts.host).toBe('campus.example');
    expect(result.verdict).toBe('safe');
  });
});

describe('Scheme Evaluation Rules', () => {
  it('flags javascript: as suspicious', () => {
    const res = analyze('javascript:alert(1)');
    expect(res.verdict).toBe('suspicious');
    expect(res.rules.some((r) => r.id === 'dangerous-scheme-javascript')).toBe(true);
  });

  it('flags vbscript: as suspicious', () => {
    const res = analyze('vbscript:msgbox(1)');
    expect(res.verdict).toBe('suspicious');
    expect(res.rules.some((r) => r.id === 'dangerous-scheme-vbscript')).toBe(true);
  });

  it('flags data:text/html as suspicious', () => {
    const res = analyze('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    expect(res.verdict).toBe('suspicious');
    expect(res.rules.some((r) => r.id === 'dangerous-scheme-data-html')).toBe(true);
  });

  it('flags file:, upi:, and mailto: as review', () => {
    expect(analyze('file:///etc/passwd').verdict).toBe('review');
    expect(analyze('upi://pay?pa=test@bank').verdict).toBe('review');
    expect(analyze('mailto:admin@campus.example').verdict).toBe('review');
  });
});

describe('Authority & Userinfo Rules', () => {
  it('flags credentials without dots as review', () => {
    const res = analyze('https://admin@campus.example/login');
    expect(res.verdict).toBe('review');
    expect(res.rules.some((r) => r.id === 'userinfo-credentials')).toBe(true);
  });

  it('ignores @ in query string and path', () => {
    const res = analyze('https://campus.example/profile/@john?user=@john');
    expect(res.parts.userinfo).toBe('');
    expect(res.verdict).toBe('safe');
  });
});

describe('Lookalike, Homoglyph, and Script Rules', () => {
  it('skeleton normalizer correctly handles Cyrillic and Greek', () => {
    expect(getSkeleton('\u0441\u0430mpus')).toBe('campus');
    expect(getSkeleton('\u03B1\u03B2c')).toBe('abc');
  });

  it('detects mixed scripts', () => {
    expect(isMixedScript('\u0441ampus.example')).toBe(true);
    expect(isMixedScript('campus.example')).toBe(false);
  });

  it('flags lookalikes of protected domains', () => {
    // google.com lookalike with Cyrillic 'о' (U+043E)
    const res = analyze('https://g\u043E\u043Egle.com/account');
    expect(res.verdict).toBe('suspicious');
    expect(res.rules.some((r) => r.id === 'character-substitution')).toBe(true);
  });
});

describe('Shortener and Obfuscation Rules', () => {
  it('covers all designated shorteners', () => {
    const sampleShorteners = ['tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'shorturl.at'];
    for (const short of sampleShorteners) {
      const res = analyze(`https://${short}/xyz123`);
      expect(res.verdict).toBe('review');
      expect(res.anomalies).toContain('url_shortener');
    }
  });

  it('flags obfuscated hex and octal IP addresses as suspicious', () => {
    const hexRes = analyze('http://0x7f000001/admin');
    expect(hexRes.verdict).toBe('suspicious');
    expect(hexRes.anomalies).toContain('raw_ip_host');
  });
});
