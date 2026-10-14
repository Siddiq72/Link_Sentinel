/**
 * COMBOSQUATTING HEURISTICS ENGINE
 * 
 * Detects adversarial domain registrations that combine legitimate brand names
 * with credential-theft or operational lure keywords (e.g. paypal-security-update.com).
 * 
 * Runs exclusively on the registrable domain label (SLD extracted via Public Suffix List),
 * maintaining zero false positives on authentic brand subdomains (e.g. security.google.com).
 */

import psl from 'psl';
import { analyzeDomain } from '../domain.js';
import { getActiveSignatures } from '../sync/ruleManager.js';

export const TARGET_BRANDS = [
  'google',
  'paypal',
  'microsoft',
  'apple',
  'amazon',
  'netflix',
  'chase',
  'wellsfargo',
  'sbi',
  'fampay',
  'binance',
  'coinbase',
  'facebook',
  'instagram',
  'dropbox',
  'adobe',
  'steam'
];

export const LURE_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verification',
  'security',
  'secure',
  'account',
  'portal',
  'update',
  'billing',
  'support',
  'auth',
  'service',
  'kyc',
  'otp',
  'wallet',
  'helpdesk',
  'claim',
  'recover'
];

const TARGET_BRANDS_SET = new Set(TARGET_BRANDS);
const LURE_KEYWORDS_SET = new Set(LURE_KEYWORDS);

/**
 * Authentic brand domains whitelist to skip legitimate corporate domains.
 */
export const AUTHENTIC_BRAND_DOMAINS = {
  google: ['google.com'],
  paypal: ['paypal.com', 'paypal.me'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'msn.com', 'azure.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de'],
  netflix: ['netflix.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'statebankofindia.com'],
  fampay: ['fampay.in', 'fampay.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  dropbox: ['dropbox.com'],
  adobe: ['adobe.com'],
  steam: ['steampowered.com', 'steamcommunity.com']
};

/**
 * Checks whether a base domain is the genuine, verified domain of the matched brand.
 * 
 * @param {string} baseDomain - Registrable domain (e.g. "paypal.com", "google.co.uk")
 * @param {string} brand - Brand token (e.g. "paypal", "google")
 * @returns {boolean}
 */
export function isAuthenticBrandDomain(baseDomain, brand) {
  if (!baseDomain || !brand) return false;
  const cleanBase = baseDomain.toLowerCase();
  const brandLower = brand.toLowerCase();

  // 1. Direct match in authentic brand domain registry
  const knownList = AUTHENTIC_BRAND_DOMAINS[brandLower];
  if (knownList && (knownList.includes(cleanBase) || knownList.some((d) => cleanBase.endsWith('.' + d)))) {
    return true;
  }

  // 2. Generic brand domain where sld is strictly the brand name (e.g. google.de, apple.co.uk)
  const parsed = psl.parse(cleanBase);
  if (parsed && parsed.sld && parsed.sld.toLowerCase() === brandLower) {
    return true;
  }

  return false;
}

/**
 * Checks a domain for combosquatting lure patterns.
 * 
 * @param {object|string} domainInput - domainInfo object, parsed context, or domain string.
 * @returns {object} Combosquatting detection result.
 */
export function checkCombosquatting(domainInput) {
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

  // Registrable domain label (SLD extracted via PSL, e.g. "paypal-security" from "sub.paypal-security.com")
  let label = domainInfo.sld || '';
  if (!label && domainInfo.domain) {
    const parsed = psl.parse(domainInfo.domain);
    label = parsed?.sld || domainInfo.domain.split('.')[0];
  }

  if (!label) {
    return { triggered: false };
  }

  // Tokenize the label by splitting on hyphens (-), underscores (_), or digits
  const tokens = label.toLowerCase().split(/[-_0-9]+/).filter(Boolean);
  if (tokens.length < 2) {
    return { triggered: false };
  }

  // Resolve threat signatures dynamically with fallback to bundled defaults
  const activeSigs = getActiveSignatures();
  const brandsList = activeSigs?.brandCatalog || TARGET_BRANDS;
  const luresList = activeSigs?.credentialLures || LURE_KEYWORDS;
  const brandsSet = new Set(brandsList);
  const luresSet = new Set(luresList);

  // Check if any token matches a brand from the target list AND at least one other token matches a lure keyword
  let matchedBrand = null;
  let brandIndex = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (brandsSet.has(tokens[i])) {
      matchedBrand = tokens[i];
      brandIndex = i;
      break;
    }
  }

  if (!matchedBrand) {
    return { triggered: false };
  }

  let matchedKeyword = null;
  for (let j = 0; j < tokens.length; j++) {
    if (j !== brandIndex && luresSet.has(tokens[j])) {
      matchedKeyword = tokens[j];
      break;
    }
  }

  if (!matchedKeyword) {
    return { triggered: false };
  }

  // Exception / Whitelist Check: If the base domain is the genuine, verified domain of that brand (e.g. paypal.com or google.com)
  const baseDomain = domainInfo.domain || '';
  if (isAuthenticBrandDomain(baseDomain, matchedBrand)) {
    return { triggered: false };
  }

  return {
    triggered: true,
    ruleId: 'combosquatting_phishing_lure',
    severity: 'suspicious',
    title: 'Combosquatting Brand Lure',
    mechanism: `Domain registers authentic brand token "${matchedBrand}" paired with high-risk keyword "${matchedKeyword}".`,
    primaryReason: `Combosquatting Detected — Domain couples authentic brand name "${matchedBrand}" with high-risk keyword "${matchedKeyword}" to mimic legitimate services.`,
    securityImpact: 'Attackers register composite brand domains to bypass typo-checkers and mislead users into surrendering credentials.'
  };
}

/**
 * Standard rule evaluator interface conforming to Link Sentinel engine rules.
 * 
 * @param {object} parsedContext
 * @returns {object} { rules, anomalies, combosquatting }
 */
export function evaluateCombosquattingRule(parsedContext) {
  const { domainInfo } = parsedContext || {};
  const result = checkCombosquatting(domainInfo);
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
    anomalies.push('combosquatting_lure');
  }

  return { rules, anomalies, combosquatting: result };
}

export default {
  TARGET_BRANDS,
  LURE_KEYWORDS,
  AUTHENTIC_BRAND_DOMAINS,
  isAuthenticBrandDomain,
  checkCombosquatting,
  evaluateCombosquattingRule
};
