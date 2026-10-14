/**
 * GENERIC SOCIAL-ENGINEERING SCAM LURE HEURISTIC
 *
 * Detects unbranded high-urgency scam, prize, and reward lure keyword pairings
 * within the registrable domain (SLD) label.
 *
 * Runs exclusively on registrable domain tokens (split by hyphens, underscores, or digits),
 * maintaining zero false positives on authentic institutional and brand domains.
 */

import psl from 'psl';
import { analyzeDomain } from '../domain.js';
import { AUTHENTIC_BRAND_DOMAINS } from './combosquattingRule.js';
import { PROTECTED_DOMAINS } from '../data/protectedDomains.js';

export const SCAM_LURE_GROUP_A = [
  'free',
  'gift',
  'prize',
  'reward',
  'bonus',
  'airdrop',
  'claim',
  'winner',
  'giveaway',
  'lottery',
  'crypto',
  'cash'
];

export const SCAM_LURE_GROUP_B = [
  'claim',
  'collect',
  'redeem',
  'payout',
  'jackpot',
  'winner',
  'survey',
  'instant',
  'reward'
];

export const SCAM_DICTIONARY = Array.from(new Set([...SCAM_LURE_GROUP_A, ...SCAM_LURE_GROUP_B]));
const SCAM_DICTIONARY_SET = new Set(SCAM_DICTIONARY);

/**
 * Checks a domain for unbranded generic social engineering scam lures.
 *
 * @param {object|string} domainInput - domainInfo object, parsed context, or domain string.
 * @returns {object} Scam lure detection result.
 */
export function checkScamLure(domainInput) {
  if (!domainInput) {
    return { triggered: false };
  }

  let domainInfo;
  if (typeof domainInput === 'string') {
    let host = domainInput.trim();
    if (host.includes('://')) {
      try {
        host = new URL(host).hostname;
      } catch {
        host = host.split('://')[1].split('/')[0];
      }
    } else {
      host = host.split('/')[0].split('?')[0].split('#')[0];
    }
    domainInfo = analyzeDomain(host);
  } else if (domainInput.domainInfo) {
    domainInfo = domainInput.domainInfo;
  } else {
    domainInfo = domainInput;
  }

  if (!domainInfo || domainInfo.isIp) {
    return { triggered: false };
  }

  // Extract registrable domain label (SLD)
  let label = domainInfo.sld || '';
  if (!label && domainInfo.domain) {
    const parsed = psl.parse(domainInfo.domain);
    label = parsed?.sld || domainInfo.domain.split('.')[0];
  }
  if (!label && domainInfo.hostname) {
    const parsed = psl.parse(domainInfo.hostname);
    label = parsed?.sld || domainInfo.hostname.split('.')[0];
  }

  if (!label) {
    return { triggered: false };
  }

  // Tokenize the SLD by splitting on hyphens (-), underscores (_), or digits
  const tokens = label.toLowerCase().split(/[-_0-9]+/).filter(Boolean);
  if (tokens.length < 2) {
    return { triggered: false };
  }

  // Find distinct matching tokens preserving order of occurrence
  const matchedTokens = [];
  for (const token of tokens) {
    if (SCAM_DICTIONARY_SET.has(token) && !matchedTokens.includes(token)) {
      matchedTokens.push(token);
    }
  }

  // Must contain 2 or more distinct tokens from the scam/prize dictionary
  if (matchedTokens.length < 2) {
    return { triggered: false };
  }

  // Authentic Brand Domains Whitelist check (safety net to prevent false alarms on verified institutions)
  const baseDomain = (domainInfo.domain || '').toLowerCase();
  for (const brand of Object.keys(AUTHENTIC_BRAND_DOMAINS)) {
    const knownList = AUTHENTIC_BRAND_DOMAINS[brand];
    if (knownList && (knownList.includes(baseDomain) || knownList.some((d) => baseDomain.endsWith('.' + d)))) {
      return { triggered: false };
    }
  }
  if (PROTECTED_DOMAINS.includes(baseDomain)) {
    return { triggered: false };
  }

  const primaryReason = `Social Engineering Lure Detected — Domain registers multiple high-pressure reward or prize lure keywords (${matchedTokens.join(', ')}) commonly used in lottery and credential-harvesting campaigns.`;
  const mechanism = `Domain registers multiple high-pressure reward or prize lure keywords (${matchedTokens.join(', ')}).`;
  const securityImpact = `Attackers use high-urgency reward tokens to manipulate user trust and bypass basic brand-specific filters.`;

  return {
    triggered: true,
    ruleId: 'social_engineering_lure',
    severity: 'suspicious',
    tag: 'SCAM LURE',
    title: 'Generic Social Engineering Lure',
    matchedTokens,
    primaryReason,
    mechanism,
    securityImpact
  };
}

/**
 * Standard rule evaluator interface conforming to Link Sentinel engine rules.
 *
 * @param {object} parsedContext
 * @returns {object} { rules, anomalies, scamLure }
 */
export function evaluateScamLureRule(parsedContext) {
  const { domainInfo } = parsedContext || {};
  const result = checkScamLure(domainInfo);
  const rules = [];
  const anomalies = [];

  if (result.triggered) {
    rules.push({
      id: result.ruleId,
      ruleId: result.ruleId,
      name: result.title,
      title: result.title,
      severity: result.severity,
      reason: result.primaryReason,
      primaryReason: result.primaryReason,
      mechanism: result.mechanism,
      securityImpact: result.securityImpact
    });
    anomalies.push('social_engineering_lure');
  }

  return { rules, anomalies, scamLure: result };
}

export default {
  SCAM_LURE_GROUP_A,
  SCAM_LURE_GROUP_B,
  SCAM_DICTIONARY,
  checkScamLure,
  evaluateScamLureRule
};
