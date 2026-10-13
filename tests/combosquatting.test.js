import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import {
  checkCombosquatting,
  evaluateCombosquattingRule,
  TARGET_BRANDS,
  LURE_KEYWORDS,
  isAuthenticBrandDomain
} from '../src/engine/rules/combosquattingRule.js';
import { getVerdictSummary, getPrimaryReason } from '../src/ui/ResultPanel.jsx';
import { getRuleBreakdown } from '../src/ui/ReasonCard.jsx';

describe('Combosquatting Heuristics Engine (Step 3)', () => {
  describe('Mandatory Evaluation Vectors', () => {
    it('Vector 1: https://paypal-security-update.com/ -> Suspicious (combosquatting_phishing_lure)', () => {
      const result = analyze('https://paypal-security-update.com/');
      expect(result.verdict).toBe('suspicious');
      expect(result.anomalies).toContain('combosquatting_lure');
      
      const rule = result.rules.find((r) => r.id === 'combosquatting_phishing_lure');
      expect(rule).toBeDefined();
      expect(rule.severity).toBe('suspicious');
      expect(rule.name).toBe('Combosquatting Brand Lure');
      expect(rule.mechanism).toContain('authentic brand token "paypal"');
      expect(rule.mechanism).toContain('high-risk keyword "security"');
      expect(rule.reason).toContain('Combosquatting Detected');
      expect(rule.securityImpact).toContain('Attackers register composite brand domains');
      expect(result.tag).toBe('COMBOSQUATTING');
      expect(result.primaryReason).toBe(rule.reason);
    });

    it('Vector 2: https://google-login-verify.net/ -> Suspicious (combosquatting_phishing_lure)', () => {
      const result = analyze('https://google-login-verify.net/');
      expect(result.verdict).toBe('suspicious');
      expect(result.anomalies).toContain('combosquatting_lure');
      
      const rule = result.rules.find((r) => r.id === 'combosquatting_phishing_lure');
      expect(rule).toBeDefined();
      expect(rule.mechanism).toContain('"google"');
      expect(rule.mechanism).toContain('"login"');
      expect(result.tag).toBe('COMBOSQUATTING');
    });

    it('Vector 3: https://security.google.com/ -> Safe (genuine subdomain, not combosquatting)', () => {
      const result = analyze('https://security.google.com/');
      expect(result.verdict).toBe('safe');
      expect(result.anomalies).not.toContain('combosquatting_lure');
      expect(result.rules.some((r) => r.id === 'combosquatting_phishing_lure')).toBe(false);
      expect(result.parts.host).toBe('security.google.com');
      expect(result.parts.registrableDomain).toBe('google.com');
    });

    it('Vector 4: https://paypal.com/ -> Safe (authentic brand domain)', () => {
      const result = analyze('https://paypal.com/');
      expect(result.verdict).toBe('safe');
      expect(result.anomalies).not.toContain('combosquatting_lure');
      expect(result.rules.some((r) => r.id === 'combosquatting_phishing_lure')).toBe(false);
      expect(result.parts.host).toBe('paypal.com');
      expect(result.parts.registrableDomain).toBe('paypal.com');
    });

    it('Vector 5: https://mysite-updates.com/ -> Safe (generic keyword without target brand match)', () => {
      const result = analyze('https://mysite-updates.com/');
      expect(result.verdict).toBe('safe');
      expect(result.anomalies).not.toContain('combosquatting_lure');
      expect(result.rules.some((r) => r.id === 'combosquatting_phishing_lure')).toBe(false);
    });

    it('Vector 6: https://fampay-kyc-verify.in/ -> Suspicious (combosquatting_phishing_lure)', () => {
      const result = analyze('https://fampay-kyc-verify.in/');
      expect(result.verdict).toBe('suspicious');
      expect(result.anomalies).toContain('combosquatting_lure');
      
      const rule = result.rules.find((r) => r.id === 'combosquatting_phishing_lure');
      expect(rule).toBeDefined();
      expect(rule.mechanism).toContain('"fampay"');
      expect(rule.mechanism).toContain('"kyc"');
      expect(result.tag).toBe('COMBOSQUATTING');
    });
  });

  describe('Direct checkCombosquatting Function API', () => {
    it('returns exact data contract when triggered', () => {
      const check = checkCombosquatting('paypal-security-update.com');
      expect(check).toEqual({
        triggered: true,
        ruleId: 'combosquatting_phishing_lure',
        severity: 'suspicious',
        title: 'Combosquatting Brand Lure',
        mechanism: 'Domain registers authentic brand token "paypal" paired with high-risk keyword "security".',
        primaryReason: 'Combosquatting Detected — Domain couples authentic brand name "paypal" with high-risk keyword "security" to mimic legitimate services.',
        securityImpact: 'Attackers register composite brand domains to bypass typo-checkers and mislead users into surrendering credentials.'
      });
    });

    it('returns { triggered: false } for null, empty, or IP addresses', () => {
      expect(checkCombosquatting(null)).toEqual({ triggered: false });
      expect(checkCombosquatting('')).toEqual({ triggered: false });
      expect(checkCombosquatting('192.168.1.1')).toEqual({ triggered: false });
    });

    it('supports delimiter tokenization with digits and underscores', () => {
      const checkUnder = checkCombosquatting('apple_verify_portal.com');
      expect(checkUnder.triggered).toBe(true);
      expect(checkUnder.mechanism).toContain('"apple"');
      expect(checkUnder.mechanism).toContain('"verify"');

      const checkDigits = checkCombosquatting('netflix99-account.com');
      expect(checkDigits.triggered).toBe(true);
      expect(checkDigits.mechanism).toContain('"netflix"');
      expect(checkDigits.mechanism).toContain('"account"');
    });

    it('detects reversed lure-before-brand pattern', () => {
      const checkReversed = checkCombosquatting('secure-microsoft-portal.net');
      expect(checkReversed.triggered).toBe(true);
      expect(checkReversed.mechanism).toContain('"microsoft"');
      expect(checkReversed.mechanism).toContain('"secure"');
    });

    it('evaluates registrable domain label regardless of arbitrary subdomains', () => {
      // Subdomain on malicious domain still detects combosquatting in SLD
      const checkSub = checkCombosquatting('portal.sub.paypal-security.com');
      expect(checkSub.triggered).toBe(true);
      expect(checkSub.mechanism).toContain('"paypal"');
      expect(checkSub.mechanism).toContain('"security"');

      // Genuine subdomain on authentic domain does not trigger
      const checkSafeSub = checkCombosquatting('login.microsoft.com');
      expect(checkSafeSub.triggered).toBe(false);
    });

    it('handles authentic brand whitelist verification correctly', () => {
      expect(isAuthenticBrandDomain('google.com', 'google')).toBe(true);
      expect(isAuthenticBrandDomain('paypal.com', 'paypal')).toBe(true);
      expect(isAuthenticBrandDomain('fampay.in', 'fampay')).toBe(true);
      expect(isAuthenticBrandDomain('paypal-security.com', 'paypal')).toBe(false);
      expect(isAuthenticBrandDomain('google-verify.net', 'google')).toBe(false);
    });
  });

  describe('UI Component Integration', () => {
    it('generates clear primary reason and summary for combosquatting', () => {
      const result = analyze('https://chase-login-portal.com/');
      expect(result.verdict).toBe('suspicious');
      
      const summary = getVerdictSummary(result);
      expect(summary).toContain('Combosquatting Detected');

      const primary = getPrimaryReason(result);
      expect(primary.label).toBe("Why it's flagged as Suspicious:");
      expect(primary.text).toContain('Combosquatting Detected');
    });

    it('provides explainable mechanism and impact in ReasonCard breakdown', () => {
      const result = analyze('https://binance-wallet-claim.com/');
      const comboRule = result.rules.find((r) => r.id === 'combosquatting_phishing_lure');
      expect(comboRule).toBeDefined();

      const breakdown = getRuleBreakdown(comboRule);
      expect(breakdown.mechanism).toContain('"binance"');
      expect(breakdown.mechanism).toContain('"wallet"');
      expect(breakdown.securityImpact).toContain('Attackers register composite brand domains');
    });
  });
});
