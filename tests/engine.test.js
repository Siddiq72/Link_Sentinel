import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { SAMPLES } from '../src/ui/ExampleChips.jsx';
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
import { getVerdictSummary, getPrimaryReason } from '../src/ui/ResultPanel.jsx';
import { getRuleBreakdown } from '../src/ui/ReasonCard.jsx';

describe('Link Sentinel Core Demo Link Vectors', () => {
  it('Vector 1: https://campus.example/notices/lab-3 -> Safe', () => {
    const result = analyze('https://campus.example/notices/lab-3');
    expect(result.verdict).toBe('safe');
    expect(result.parts.host).toBe('campus.example');
    expect(result.parts.registrableDomain).toBe('campus.example');
    expect(result.parts.protocol).toBe('https://');
    expect(result.parts.path).toBe('/notices/lab-3');
    expect(result.anomalies).toHaveLength(0);
  });

  it('analyzing "https://campus.example/notices/lab-3" gives path "/notices/lab-3"', () => {
    const result = analyze('https://campus.example/notices/lab-3');
    expect(result.parts.path).toBe('/notices/lab-3');
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
    expect(analyze('upi://pay?pa=campus@bank').verdict).toBe('review');
    expect(analyze('mailto:admin@campus.example').verdict).toBe('review');
  });

  it('sets correct http note text when protocol is unencrypted http', () => {
    const res = analyze('http://campus.example/test');
    const httpRule = res.rules.find((r) => r.id === 'insecure-scheme');
    expect(httpRule).toBeDefined();
    expect(httpRule.reason).toBe('This link uses http, not https, so data sent to it is not encrypted.');
  });

  it('sets correct SAFE note text when link has no threats', () => {
    const res = analyze('https://campus.example/notices/lab-3');
    const safeRule = res.rules.find((r) => r.id === 'standard-route');
    expect(safeRule).toBeDefined();
    expect(safeRule.reason).toBe('This link uses https. No deception signals were found in its structure.');
  });

  it('falls back gracefully to Suspicious: Malformed link for malformed URIs', () => {
    const malformed1 = analyze('https://::');
    expect(malformed1.verdict).toBe('suspicious');
    expect(malformed1.anomalies).toContain('malformed_uri_syntax');
    expect(malformed1.rules.some((r) => r.id === 'malformed-link')).toBe(true);

    const malformed2 = analyze('https://campus.example:999999');
    expect(malformed2.verdict).toBe('suspicious');
    expect(malformed2.anomalies).toContain('malformed_uri_syntax');
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

describe('Example Template Chips Presentation Audit', () => {
  it('contains all 7 presentation slide vectors with correct deterministic verdicts', () => {
    expect(SAMPLES).toHaveLength(7);
    const expected = {
      'Ordinary': 'safe',
      '@ trick': 'suspicious',
      'Lookalike': 'suspicious',
      'Public IP': 'suspicious',
      'Private IP': 'review',
      'Shortener': 'review',
      'Safe: @ in query': 'safe'
    };
    for (const sample of SAMPLES) {
      expect(expected[sample.label]).toBeDefined();
      const res = analyze(sample.url);
      expect(res.verdict).toBe(expected[sample.label]);
    }
  });
});

describe('Plain-Language Verdict Summary Sentences', () => {
  it('Suspicious (@ trick): generates "The real host is <host>, not <decoy>."', () => {
    const res = analyze('https://campus.example@other.example/login');
    const summary = getVerdictSummary(res);
    expect(summary).toBe('The real host is other.example, not campus.example.');
  });

  it('Suspicious (lookalike): generates "This domain imitates <real domain> using a look-alike character."', () => {
    const res = analyze('https://\u0441ampus.example/login');
    const summary = getVerdictSummary(res);
    expect(summary).toBe('This domain imitates campus.example using a look-alike character.');
  });

  it('Review: uses the first Review reason for private IP', () => {
    const res = analyze('http://192.168.1.10/');
    const summary = getVerdictSummary(res);
    expect(summary).toBe('Host is a private local area network IP address (RFC 1918). Destination only accessible on internal networks.');
  });

  it('Review: uses the first Review reason for shorteners', () => {
    const res = analyze('https://bit.ly/3abcXYZ');
    const summary = getVerdictSummary(res);
    expect(summary).toBe('Shortened link: the real destination is hidden and cannot be checked offline.');
  });

  it('Safe: keeps the SAFE caveat', () => {
    const res = analyze('https://campus.example/notices/lab-3');
    const summary = getVerdictSummary(res);
    expect(summary).toBe('No deception signals found. This is not a guarantee.');
  });
});

describe('Primary Reason Callout Section on Verdict Banners', () => {
  it('Suspicious (@ trick): generates distinct Why it is flagged as Suspicious callout', () => {
    const res = analyze('https://campus.example@other.example/login');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toBe("Authority Routing Decoy — The link is attempting to disguise its destination. The text before '@' impersonates a domain, but the browser will actually connect to the real host 'other.example'.");
  });

  it('Suspicious (lookalike): generates distinct Homoglyph callout', () => {
    const res = analyze('https://\u0441ampus.example/login');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toBe("Domain Impersonation / Homoglyph — The domain uses visually deceptive characters to imitate 'campus.example', misleading users into trusting a spoofed destination.");
  });

  it('Suspicious (raw IP): generates distinct Direct IP Authority callout', () => {
    const res = analyze('http://192.0.2.45/signin');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toBe("Direct IP Authority — The link uses a raw unmapped IP address (192.0.2.45) rather than an authenticated domain name, commonly used to bypass domain-based security filters.");
  });

  it('Suspicious (dangerous scheme): generates distinct Executable Scheme callout', () => {
    const res = analyze('javascript:alert(1)');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toBe("Executable Scheme — Protocol 'javascript:' can run scripts or render malicious code locally.");
  });

  it('Suspicious (malformed): generates distinct Malformed Structure callout', () => {
    const res = analyze('https://::');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toBe("Malformed Structure — The link syntax is invalid or corrupted, preventing safe destination parsing.");
  });

  it('Review (shortener): generates distinct Hidden Destination callout', () => {
    const res = analyze('https://bit.ly/3abcXYZ');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe('Why review is required:');
    expect(reason.text).toBe('Hidden Destination — Shortened links conceal the real target host and cannot be resolved safely in an offline environment without outbound network requests.');
  });

  it('Review (private IP): generates distinct Internal Network Target callout', () => {
    const res = analyze('http://192.168.1.10/');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe('Why review is required:');
    expect(reason.text).toBe('Internal Network Target — The address belongs to a private RFC 1918 subnet (192.168.1.10). It is only reachable within an internal network or local hardware.');
  });

  it('Review (non-web scheme): generates distinct External Application Handler callout', () => {
    const res = analyze('upi://pay?pa=campus@bank');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe('Why review is required:');
    expect(reason.text).toBe("External Application Handler — Scheme 'upi:' triggers an external desktop or mobile application.");
  });

  it('Safe: generates distinct Classification basis callout', () => {
    const res = analyze('https://campus.example/notices/lab-3');
    const reason = getPrimaryReason(res);
    expect(reason.label).toBe('Classification basis:');
    expect(reason.text).toBe('No deception signals detected — Standard authority formatting and valid HTTPS protocol with no homoglyphs, credentials, or redirection patterns found.');
  });
});

describe('ReasonCard Mechanism and Security Impact Breakdown', () => {
  it('distinguishes Mechanism and Security Impact for authority routing trap', () => {
    const breakdown = getRuleBreakdown({ id: 'authority-routing-trap', severity: 'suspicious' });
    expect(breakdown.mechanism).toContain('URL authority contains userinfo');
    expect(breakdown.securityImpact).toContain('Deceives users into believing');
  });

  it('distinguishes Mechanism and Security Impact for homoglyph substitution', () => {
    const breakdown = getRuleBreakdown({ id: 'character-substitution', severity: 'suspicious' });
    expect(breakdown.mechanism).toContain('homoglyphs');
    expect(breakdown.securityImpact).toContain('mislead users into entering credentials');
  });

  it('distinguishes Mechanism and Security Impact for unencrypted HTTP', () => {
    const breakdown = getRuleBreakdown({ id: 'insecure-scheme', severity: 'note' });
    expect(breakdown.mechanism).toContain('Unencrypted HTTP scheme');
    expect(breakdown.securityImpact).toContain('Man-in-the-Middle');
  });

  it('distinguishes Mechanism and Security Impact for standard route', () => {
    const breakdown = getRuleBreakdown({ id: 'standard-route', severity: 'note' });
    expect(breakdown.mechanism).toContain('Standard institutional domain route');
    expect(breakdown.securityImpact).toContain('Connection is encrypted in transit');
  });
});
