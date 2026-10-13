import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { parseInput } from '../src/engine/parse.js';
import { evaluateAuthorityRule } from '../src/engine/rules/authorityRule.js';

describe('Step 2: Hardening & Judge-Proofing Security Suite', () => {
  describe('1. Input Clamping & Sanitization', () => {
    it('throws descriptive error prompt on empty and whitespace inputs without crashing', () => {
      expect(() => analyze('')).toThrow(/Please enter a valid link|Please enter a link or scan a QR code to inspect/);
      expect(() => analyze('   ')).toThrow(/Please enter a valid link|Please enter a link or scan a QR code to inspect/);
      expect(() => analyze('\t\n\r')).toThrow(/Please enter a valid link|Please enter a link or scan a QR code to inspect/);
      expect(() => analyze(null)).toThrow(/Please enter a valid link|Please enter a link or scan a QR code to inspect/);
      expect(() => analyze(undefined)).toThrow(/Please enter a valid link|Please enter a link or scan a QR code to inspect/);
    });

    it('enforces 2048-character length ceiling on 100,000-character payload in under 50ms', () => {
      const hugeInput = 'https://campus.example/path?' + 'param='.repeat(20000);
      expect(hugeInput.length).toBeGreaterThan(100000);

      const startTime = performance.now();
      const result = analyze(hugeInput);
      const elapsed = performance.now() - startTime;

      expect(elapsed).toBeLessThan(50);
      expect(result.verdict).toBe('review');
      expect(result.tag).toBe('EXCESSIVE LENGTH');
      expect(result.primaryReason).toBe(
        'Oversized Input — Link length exceeds standard URL limits (2048 characters). Truncated to prevent regex resource exhaustion.'
      );
      expect(result.anomalies).toContain('excessive_length');
      expect(result.rules.some((r) => r.id === 'excessive-length')).toBe(true);
      expect(result.parts).toBeDefined();
    });

    it('detects two links pasted together with whitespace or newlines', () => {
      const spaceSeparated = analyze('https://campus.example/notice https://phish.example/login');
      expect(spaceSeparated.verdict).toBe('review');
      expect(spaceSeparated.tag).toBe('MULTIPLE TARGETS');
      expect(spaceSeparated.primaryReason).toBe(
        'Multiple destinations detected — Link Sentinel inspects one link at a time. Please test links individually.'
      );
      expect(spaceSeparated.anomalies).toContain('multiple_targets');

      const newlineSeparated = analyze('https://campus.example\nhttps://portal.example');
      expect(newlineSeparated.verdict).toBe('review');
      expect(newlineSeparated.tag).toBe('MULTIPLE TARGETS');

      const mixedSeparated = analyze('https://a.example/test\r\nhttp://b.example/test');
      expect(mixedSeparated.verdict).toBe('review');
      expect(mixedSeparated.tag).toBe('MULTIPLE TARGETS');
    });

    it('handles emoji and random gibberish without false safe verdicts', () => {
      const emojiRes = analyze('🚀🔥🦄');
      expect(emojiRes.verdict).toBe('review');
      expect(emojiRes.tag).toBe('UNRECOGNIZED INPUT');
      expect(emojiRes.primaryReason).toBe(
        'Unrecognized structure — Input does not match a valid URL, network intent, or recognized barcode format.'
      );
      expect(emojiRes.anomalies).toContain('unrecognized_input');

      const gibberishRes = analyze('sdkjfhskdjhf');
      expect(gibberishRes.verdict).toBe('review');
      expect(gibberishRes.tag).toBe('UNRECOGNIZED INPUT');
      expect(gibberishRes.primaryReason).toBe(
        'Unrecognized structure — Input does not match a valid URL, network intent, or recognized barcode format.'
      );

      const fakeTldRes = analyze('myrandominput.invalidgibberishtld123');
      expect(fakeTldRes.verdict).toBe('review');
      expect(fakeTldRes.tag).toBe('UNRECOGNIZED INPUT');
    });
  });

  describe('2. Authority & Encoding Hardening', () => {
    it('flags %40 percent-encoded @ bypass as suspicious Authority Routing Decoy', () => {
      const res = analyze('https://campus.example%40other.example/');
      expect(res.verdict).toBe('suspicious');
      expect(res.parts.host).toBe('other.example');
      expect(res.parts.userinfo).toContain('campus.example');
      expect(res.anomalies).toContain('userinfo_decoy');
      expect(res.rules.some((r) => r.id === 'authority-routing-trap')).toBe(true);
    });

    it('flags %2540 double-encoded @ bypass as suspicious Authority Routing Decoy', () => {
      const res = analyze('https://campus.example%2540other.example/');
      expect(res.verdict).toBe('suspicious');
      expect(res.parts.host).toBe('other.example');
      expect(res.anomalies).toContain('userinfo_decoy');
      expect(res.rules.some((r) => r.id === 'authority-routing-trap')).toBe(true);
    });

    it('normalizes trailing DNS root dots (campus.example.) and case insensitivity to match clean domain', () => {
      const clean = analyze('https://campus.example/notices/lab-3');
      const trailingDot = analyze('https://campus.example./notices/lab-3');
      const uppercase = analyze('HTTPS://CAMPUS.EXAMPLE/notices/lab-3');
      const uppercaseTrailing = analyze('https://CAMPUS.EXAMPLE./notices/lab-3');

      expect(trailingDot.verdict).toBe(clean.verdict);
      expect(trailingDot.verdict).toBe('safe');
      expect(trailingDot.parts.host).toBe('campus.example');
      expect(trailingDot.parts.registrableDomain).toBe('campus.example');

      expect(uppercase.verdict).toBe(clean.verdict);
      expect(uppercase.parts.host).toBe('campus.example');

      expect(uppercaseTrailing.verdict).toBe(clean.verdict);
      expect(uppercaseTrailing.parts.host).toBe('campus.example');

      const bareClean = analyze('campus.example');
      const bareTrailing = analyze('campus.example.');
      expect(bareTrailing.verdict).toBe(bareClean.verdict);
      expect(bareTrailing.parts.host).toBe('campus.example');
    });

    it('escalates fully Cyrillic / non-Latin domains to Review with NON-LATIN SCRIPT tag', () => {
      const idnRes = analyze('https://президент.рф');
      expect(idnRes.verdict).toBe('review');
      expect(idnRes.tag).toBe('NON-LATIN SCRIPT');
      expect(idnRes.primaryReason).toBe(
        'Internationalized Domain Name — Uses full non-Latin script. Cannot verify authority against Latin-alphabet targets offline.'
      );
      expect(idnRes.anomalies).toContain('non_latin_script');
      expect(idnRes.rules.some((r) => r.id === 'non-latin-script')).toBe(true);

      const bareIdn = analyze('президент.рф');
      expect(bareIdn.verdict).toBe('review');
      expect(bareIdn.tag).toBe('NON-LATIN SCRIPT');
    });

    it('handles special IP variants: loopback IPv6 [::1], hex IP 0x7f.1, and full-width numbers', () => {
      // IPv6 Loopback -> Review
      const ipv6Res = analyze('http://[::1]/admin');
      expect(ipv6Res.verdict).toBe('review');
      expect(ipv6Res.anomalies).toContain('private_ip_host');
      expect(ipv6Res.rules.some((r) => r.id === 'private-ip-host')).toBe(true);

      const bareIpv6 = analyze('[::1]');
      expect(bareIpv6.verdict).toBe('review');
      expect(bareIpv6.anomalies).toContain('private_ip_host');

      // Hex IP notation -> Suspicious (obfuscated numeric host)
      const hexRes = analyze('http://0x7f.1/test');
      expect(hexRes.verdict).toBe('suspicious');
      expect(hexRes.anomalies).toContain('raw_ip_host');
      expect(hexRes.rules.some((r) => r.id === 'obfuscated-ip-host')).toBe(true);

      // Full-width Unicode numbers -> resolves to 127.0.0.1 (private loopback)
      const unicodeIpRes = analyze('http://①②⑦.0.0.1/');
      expect(unicodeIpRes.verdict).toBe('review');
      expect(unicodeIpRes.anomalies).toContain('private_ip_host');
    });

    it('classifies executable data URIs immediately as suspicious with EXECUTABLE DATA tag', () => {
      const htmlData = analyze('data:text/html,<script>alert(document.cookie)</script>');
      expect(htmlData.verdict).toBe('suspicious');
      expect(htmlData.tag).toBe('EXECUTABLE DATA');
      expect(htmlData.primaryReason).toBe(
        'Data URI Scheme — Encodes inline executable HTML or script content directly inside the link.'
      );
      expect(htmlData.anomalies).toContain('dangerous_scheme');
      expect(htmlData.anomalies).toContain('executable_data');
      expect(htmlData.rules.some((r) => r.id === 'dangerous-scheme-data-html')).toBe(true);

      const appData = analyze('data:application/javascript;base64,YWxlcnQoMSk=');
      expect(appData.verdict).toBe('suspicious');
      expect(appData.tag).toBe('EXECUTABLE DATA');
      expect(appData.primaryReason).toBe(
        'Data URI Scheme — Encodes inline executable HTML or script content directly inside the link.'
      );
    });
  });

  describe('3. Global Safety-Net & Data Contract Conformance', () => {
    it('guarantees complete Link Sentinel result schema across all adversarial edge cases', () => {
      const adversarialInputs = [
        'https://campus.example%40other.example/',
        'https://campus.example%2540other.example/',
        'https://campus.example.',
        'data:text/html,<script>alert(1)</script>',
        'http://[::1]/',
        'http://0x7f.1/',
        'http://①②⑦.0.0.1/',
        'https://президент.рф',
        '🚀🔥🦄',
        'sdkjfhskdjhf',
        'https://a.com https://b.com',
        'https://::',
        'https://campus.example:999999'
      ];

      for (const input of adversarialInputs) {
        const result = analyze(input);
        expect(result).toBeDefined();
        expect(typeof result.verdict).toBe('string');
        expect(['safe', 'review', 'suspicious']).toContain(result.verdict);
        expect(result.parts).toBeDefined();
        expect(typeof result.parts).toBe('object');
        expect(Array.isArray(result.anomalies)).toBe(true);
        expect(Array.isArray(result.rules)).toBe(true);
        expect(Array.isArray(result.passedRules)).toBe(true);
      }
    });

    it('preserves safe verdict when %40 appears strictly inside query parameters', () => {
      const res = analyze('https://portal.campus.example:8443/forms?contact=lab%40campus.example');
      expect(res.verdict).toBe('safe');
      expect(res.parts.host).toBe('portal.campus.example');
      expect(res.anomalies).not.toContain('userinfo_decoy');
    });

    it('throws expected error when parseInput is called with empty or whitespace input', () => {
      expect(() => parseInput('')).toThrow(/Please enter a valid link/);
      expect(() => parseInput('   ')).toThrow(/Please enter a valid link/);
    });

    it('exports evaluateAuthorityRule from engine and authorityRule.js', () => {
      expect(typeof evaluateAuthorityRule).toBe('function');
    });
  });
});
