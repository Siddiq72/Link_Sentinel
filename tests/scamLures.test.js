import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { checkSpecialTld, evaluateSpecialTldRule, RESERVED_TLDS } from '../src/engine/rules/specialTldRule.js';
import { checkScamLure, evaluateScamLureRule, SCAM_DICTIONARY } from '../src/engine/rules/scamLureRule.js';
import { getVerdictSummary, getPrimaryReason } from '../src/ui/ResultPanel.jsx';
import { getRuleBreakdown } from '../src/ui/ReasonCard.jsx';

describe('1. Reserved & Special-Use TLD Guard (RFC 2606 / RFC 6761)', () => {
  it('flags .invalid domain as review with reserved_special_tld rule', () => {
    const res = analyze('http://test-site.invalid/');
    expect(res.verdict).toBe('review');
    expect(res.tag).toBe('RESERVED TLD');
    expect(res.anomalies).toContain('reserved_special_tld');

    const rule = res.rules.find((r) => r.id === 'reserved_special_tld');
    expect(rule).toBeDefined();
    expect(rule.name).toBe('Special-Use / Non-Routable Domain');
    expect(rule.severity).toBe('review');
    expect(rule.reason).toBe(
      'Reserved TLD Detected — The domain uses a special-use extension (.invalid) under RFC 2606 that cannot be registered or resolved on the public Internet.'
    );
    expect(rule.mechanism).toBe('TLD matches permanently reserved non-routable namespace (.invalid).');
    expect(rule.securityImpact).toBe('Cannot be verified via public DNS and cannot establish authenticated connections.');
  });

  it('flags .test, .localhost, and non-exempt .example as review', () => {
    const testRes = analyze('http://gateway.test/login');
    expect(testRes.verdict).toBe('review');
    expect(testRes.tag).toBe('RESERVED TLD');
    expect(testRes.anomalies).toContain('reserved_special_tld');

    const localRes = analyze('http://app.localhost:3000/');
    expect(localRes.verdict).toBe('review');
    expect(localRes.tag).toBe('RESERVED TLD');

    const bareLocal = analyze('http://localhost:8080/');
    expect(bareLocal.verdict).toBe('review');
    expect(bareLocal.tag).toBe('RESERVED TLD');

    const unexemptExample = analyze('https://random-phish.example/account');
    expect(unexemptExample.verdict).toBe('review');
    expect(unexemptExample.tag).toBe('RESERVED TLD');
  });

  it('exempts legitimate documentation domains (campus.example) from reserved TLD rule', () => {
    const campusRes = analyze('https://campus.example/notices/lab-3');
    expect(campusRes.verdict).toBe('safe');
    expect(campusRes.anomalies).not.toContain('reserved_special_tld');

    const portalRes = analyze('https://portal.campus.example:8443/forms');
    expect(portalRes.verdict).toBe('safe');
    expect(portalRes.anomalies).not.toContain('reserved_special_tld');
  });
});

describe('2. Generic Social-Engineering Scam Lure Heuristic', () => {
  it('flags multi-token lure https://instant-cash-reward.com/ as suspicious', () => {
    const res = analyze('https://instant-cash-reward.com/');
    expect(res.verdict).toBe('suspicious');
    expect(res.tag).toBe('SCAM LURE');
    expect(res.anomalies).toContain('social_engineering_lure');

    const rule = res.rules.find((r) => r.id === 'social_engineering_lure');
    expect(rule).toBeDefined();
    expect(rule.severity).toBe('suspicious');
    expect(rule.name).toBe('Generic Social Engineering Lure');
    expect(rule.reason).toContain('instant, cash, reward');
    expect(rule.securityImpact).toBe(
      'Attackers use high-urgency reward tokens to manipulate user trust and bypass basic brand-specific filters.'
    );
  });

  it('evaluates http://free-prize-claim.invalid/winner as suspicious with both rules triggered', () => {
    const res = analyze('http://free-prize-claim.invalid/winner');
    expect(res.verdict).toBe('suspicious');
    expect(res.tag).toBe('SCAM LURE');
    expect(res.anomalies).toContain('social_engineering_lure');
    expect(res.anomalies).toContain('reserved_special_tld');

    expect(res.rules.some((r) => r.id === 'social_engineering_lure')).toBe(true);
    expect(res.rules.some((r) => r.id === 'reserved_special_tld')).toBe(true);
  });

  it('does NOT trigger multi-token heuristic on single lure token (https://my-free-app.com/)', () => {
    const res = analyze('https://my-free-app.com/');
    expect(res.verdict).toBe('safe');
    expect(res.anomalies).not.toContain('social_engineering_lure');
    expect(res.rules.some((r) => r.id === 'social_engineering_lure')).toBe(false);
  });

  it('detects unbranded prize and airdrop variations', () => {
    const airdropRes = analyze('https://crypto-airdrop.xyz/');
    expect(airdropRes.verdict).toBe('suspicious');
    expect(airdropRes.tag).toBe('SCAM LURE');

    const winnerRes = analyze('https://winner-reward.net/');
    expect(winnerRes.verdict).toBe('suspicious');
    expect(winnerRes.tag).toBe('SCAM LURE');

    const claimRes = analyze('https://claim-reward-now.org/');
    expect(claimRes.verdict).toBe('suspicious');
    expect(claimRes.tag).toBe('SCAM LURE');
  });
});

describe('3. Whitelist Preservation of Authentic Domains', () => {
  it('amazon.com remains strictly Safe', () => {
    const resHttps = analyze('https://amazon.com/');
    expect(resHttps.verdict).toBe('safe');
    expect(resHttps.anomalies).toHaveLength(0);

    const resBare = analyze('amazon.com');
    expect(resBare.verdict).toBe('safe');
    expect(resBare.anomalies).toHaveLength(0);
  });

  it('paypal.com remains strictly Safe', () => {
    const resHttps = analyze('https://paypal.com/');
    expect(resHttps.verdict).toBe('safe');
    expect(resHttps.anomalies).toHaveLength(0);

    const resBare = analyze('paypal.com');
    expect(resBare.verdict).toBe('safe');
    expect(resBare.anomalies).toHaveLength(0);
  });

  it('google.com remains strictly Safe', () => {
    const resHttps = analyze('https://google.com/');
    expect(resHttps.verdict).toBe('safe');
    expect(resHttps.anomalies).toHaveLength(0);

    const resBare = analyze('google.com');
    expect(resBare.verdict).toBe('safe');
    expect(resBare.anomalies).toHaveLength(0);
  });

  it('subdomains on authentic domains (e.g. rewards.google.com) remain Safe', () => {
    const res = analyze('https://rewards.google.com/');
    expect(res.verdict).toBe('safe');
    expect(res.anomalies).not.toContain('social_engineering_lure');
  });
});

describe('4. UI & Explainability Breakdown Integration', () => {
  it('generates correct VerdictBanner reason and summary for SCAM LURE', () => {
    const res = analyze('https://instant-cash-reward.com/');
    const summary = getVerdictSummary(res);
    expect(summary).toContain('instant, cash, reward');

    const reason = getPrimaryReason(res);
    expect(reason.label).toBe("Why it's flagged as Suspicious:");
    expect(reason.text).toContain('instant, cash, reward');
  });

  it('generates correct VerdictBanner reason and summary for RESERVED TLD', () => {
    const res = analyze('http://test-site.invalid/');
    const summary = getVerdictSummary(res);
    expect(summary).toContain('RFC 2606');

    const reason = getPrimaryReason(res);
    expect(reason.label).toBe('Why review is required:');
    expect(reason.text).toContain('RFC 2606');
  });

  it('populates explainable mechanism and securityImpact in ReasonCard breakdown', () => {
    const scamBreakdown = getRuleBreakdown({ id: 'social_engineering_lure' });
    expect(scamBreakdown.mechanism).toBeDefined();
    expect(scamBreakdown.securityImpact).toContain('Attackers use high-urgency reward tokens');

    const tldBreakdown = getRuleBreakdown({ id: 'reserved_special_tld' });
    expect(tldBreakdown.mechanism).toBeDefined();
    expect(tldBreakdown.securityImpact).toContain('Cannot be verified via public DNS');
  });
});
