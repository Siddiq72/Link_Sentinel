import React from 'react';
import VerdictBanner from './VerdictBanner';
import UrlTokens from './UrlTokens';
import ReasonCard from './ReasonCard';

export default function ResultPanel({ result }) {
  if (!result) return null;

  const { verdict, parts, anomalies = [], rules = [], passedRules = [] } = result;

  // Determine tag for banner
  let tag = 'ANALYSIS';
  if (verdict === 'safe') {
    tag = 'LEGITIMATE';
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

  return (
    <div className="flex flex-col gap-5" aria-live="polite">
      {/* 1. Verdict Banner */}
      <VerdictBanner verdict={verdict} tag={tag} />

      {/* 2. URL Anatomy Breakdown */}
      <UrlTokens parts={parts} anomalies={anomalies} verdict={verdict} />

      {/* 3. Explainable Rule Breakdown */}
      <ReasonCard rules={rules} passedRules={passedRules} />
    </div>
  );
}
