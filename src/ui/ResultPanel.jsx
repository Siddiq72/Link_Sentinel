import React from 'react';
import VerdictBanner from './VerdictBanner';
import UrlTokens from './UrlTokens';
import ReasonCard from './ReasonCard';

export function getVerdictSummary({ verdict, parts, anomalies = [], rules = [] }) {
  if (verdict === 'safe') {
    return 'No deception signals found. This is not a guarantee.';
  }

  if (verdict === 'suspicious') {
    // 1. Suspicious (@ trick): "The real host is <host>, not <decoy>."
    const isUserinfoDecoy = anomalies.includes('userinfo_decoy') || rules.some((r) => r.id === 'authority-routing-trap');
    if (isUserinfoDecoy) {
      const host = parts?.host || '';
      const rawUserinfo = parts?.userinfo || '';
      const decoy = rawUserinfo.replace(/@$/, '').split(':')[0];
      return `The real host is ${host}, not ${decoy}.`;
    }

    // 2. Suspicious (lookalike): "This domain imitates <real domain> using a look-alike character."
    const isLookalike = anomalies.includes('homoglyph_cyrillic') ||
      anomalies.includes('homoglyph_greek') ||
      anomalies.includes('lookalike_domain') ||
      rules.some((r) => r.id === 'character-substitution' || r.id === 'mixed-script-detection');

    if (isLookalike) {
      const lookalikeRule = rules.find((r) => r.id === 'character-substitution' || r.id === 'mixed-script-detection');
      let realDomain = '';
      if (lookalikeRule) {
        const match = lookalikeRule.reason.match(/imitates\s+([^.\s]+(?:\.[^.\s]+)+)/i) ||
          lookalikeRule.reason.match(/protected domain\s+([^.\s]+(?:\.[^.\s]+)+)/i);
        if (match) {
          realDomain = match[1].replace(/[.,;:)]+$/, '');
        }
      }
      if (!realDomain) {
        realDomain = 'campus.example';
      }
      return `This domain imitates ${realDomain} using a look-alike character.`;
    }

    // 3. Fallback for other suspicious verdicts: first suspicious rule reason
    const firstSuspiciousRule = rules.find((r) => r.severity?.toLowerCase() === 'suspicious');
    if (firstSuspiciousRule) {
      return firstSuspiciousRule.reason;
    }
    return 'Clear structural deception detected.';
  }

  if (verdict === 'review') {
    // Review: use the first Review reason.
    const firstReviewRule = rules.find((r) => r.severity?.toLowerCase() === 'review');
    if (firstReviewRule) {
      return firstReviewRule.reason;
    }
    return 'Review needed: this link destination cannot be fully verified offline.';
  }

  return '';
}

export default function ResultPanel({ result }) {
  if (!result) return null;

  const { verdict, parts, anomalies = [], rules = [], passedRules = [] } = result;

  // Determine tag for banner
  let tag = 'ANALYSIS';
  if (verdict === 'safe') {
    tag = 'NO RED FLAGS';
  } else if (anomalies.includes('malformed_uri_syntax')) {
    tag = 'MALFORMED';
  } else if (anomalies.includes('userinfo_decoy')) {
    tag = '@ TRICK';
  } else if (anomalies.includes('homoglyph_cyrillic')) {
    tag = 'LOOKALIKE';
  } else if (anomalies.includes('url_shortener')) {
    tag = 'SHORTENER';
  } else if (anomalies.includes('raw_ip_host')) {
    tag = 'IP HOST';
  } else if (verdict === 'review') {
    tag = 'REVIEW';
  } else if (verdict === 'suspicious') {
    tag = 'SUSPICIOUS';
  }

  const summary = getVerdictSummary({ verdict, parts, anomalies, rules });

  return (
    <div className="flex flex-col gap-5" aria-live="polite">
      {/* 1. Verdict Banner */}
      <VerdictBanner verdict={verdict} tag={tag} summary={summary} />

      {/* 2. URL Anatomy Breakdown */}
      <UrlTokens parts={parts} anomalies={anomalies} verdict={verdict} />

      {/* 3. Explainable Rule Breakdown */}
      <ReasonCard rules={rules} passedRules={passedRules} />
    </div>
  );
}
