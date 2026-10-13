/**
 * Evaluates hostnames and domains against PROTECTED_DOMAINS using skeleton mappings
 * and fastest-levenshtein edit distance.
 * Flags:
 * - Lookalikes and homoglyphs of protected domains as "suspicious"
 * - Mixed Cyrillic/Greek/Latin scripts as "suspicious"
 */

import { distance } from 'fastest-levenshtein';
import { PROTECTED_DOMAINS } from '../data/protectedDomains.js';
import { getSkeleton, hasCyrillic, hasGreek, isMixedScript, computeLookalikeDiff } from '../data/confusables.js';

export function evaluateLookalikeRule(parsedContext) {
  const { domainInfo } = parsedContext;
  const unicodeHost = domainInfo?.unicodeHostname || '';
  const domain = domainInfo?.domain || unicodeHost;

  const rules = [];
  const anomalies = [];

  if (!unicodeHost || domainInfo?.isIp) {
    return { rules, anomalies };
  }

  const containsCyrillic = hasCyrillic(unicodeHost);
  const containsGreek = hasGreek(unicodeHost);
  const mixed = isMixedScript(unicodeHost);

  if (containsCyrillic) {
    anomalies.push('homoglyph_cyrillic');
  }
  if (containsGreek) {
    anomalies.push('homoglyph_greek');
  }
  if (mixed) {
    anomalies.push('mixed_script');
  }

  const skeletonDomain = getSkeleton(domain);
  const skeletonHost = getSkeleton(unicodeHost);

  let detectedImitation = null;
  let imitationReason = '';

  for (const protectedTarget of PROTECTED_DOMAINS) {
    // If exact match without any non-Latin or confusables, it is the legitimate domain
    if ((domain === protectedTarget || unicodeHost === protectedTarget) && !containsCyrillic && !containsGreek) {
      continue;
    }

    // Check if skeleton directly maps to the protected domain
    if (skeletonDomain === protectedTarget || skeletonHost === protectedTarget || skeletonHost.endsWith('.' + protectedTarget)) {
      if (domain !== protectedTarget || containsCyrillic || containsGreek) {
        detectedImitation = protectedTarget;
        imitationReason = `Flagged: this domain uses a look-alike character and imitates ${protectedTarget}.`;
        break;
      }
    }

    // Check Levenshtein edit distance on domain or skeleton
    const editDistDomain = distance(domain, protectedTarget);
    const editDistSkeleton = distance(skeletonDomain, protectedTarget);

    if (editDistDomain > 0 && editDistDomain <= 2) {
      detectedImitation = protectedTarget;
      imitationReason = `Flagged: this domain has an edit distance of ${editDistDomain} from protected domain ${protectedTarget}.`;
      break;
    }

    if (editDistSkeleton > 0 && editDistSkeleton <= 2) {
      detectedImitation = protectedTarget;
      imitationReason = `Flagged: normalized domain skeleton imitates protected target ${protectedTarget}.`;
      break;
    }
  }

  let diff = null;
  if (detectedImitation) {
    diff = computeLookalikeDiff(unicodeHost, detectedImitation);
    rules.push({
      id: 'character-substitution',
      name: 'Character Substitution',
      severity: 'suspicious',
      reason: imitationReason
    });
    if (!anomalies.includes('lookalike_domain')) {
      anomalies.push('lookalike_domain');
    }
  } else if (mixed) {
    rules.push({
      id: 'mixed-script-detection',
      name: 'Mixed Script Detection',
      severity: 'suspicious',
      reason: 'Flagged: domain contains mixed or non-standard scripts capable of visual spoofing.'
    });
  } else if (!/[a-zA-Z]/.test(unicodeHost) && /[^\x00-\x7F]/.test(unicodeHost)) {
    rules.push({
      id: 'non-latin-script',
      name: 'Internationalized Domain Name',
      severity: 'review',
      reason: 'Internationalized Domain Name — Uses full non-Latin script. Cannot verify authority against Latin-alphabet targets offline.'
    });
    anomalies.push('non_latin_script');
  } else if (containsCyrillic || containsGreek) {
    rules.push({
      id: 'mixed-script-detection',
      name: 'Mixed Script Detection',
      severity: 'suspicious',
      reason: 'Flagged: domain contains mixed or non-standard scripts capable of visual spoofing.'
    });
  }

  return { rules, anomalies, diff };
}

export default evaluateLookalikeRule;
