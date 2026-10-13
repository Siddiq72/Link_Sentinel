import React from 'react';
import VerdictBanner from './VerdictBanner';
import UrlTokens from './UrlTokens';
import ReasonCard from './ReasonCard';
import LookalikeDiffCard from './LookalikeDiffCard';
import UpiPayloadCard from './payloads/UpiPayloadCard';
import WifiPayloadCard from './payloads/WifiPayloadCard';
import TextPayloadCard from './payloads/TextPayloadCard';

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

export function getPrimaryReason(arg) {
  const { verdict, parts = {}, anomalies = [], rules = [] } = arg || {};
  if (verdict === 'safe') {
    if (rules.some((r) => r.id === 'non-executable-text') || arg?.payloadType === 'TEXT') {
      return {
        label: 'Classification basis:',
        text: 'Non-Executable Text — This QR contains plain descriptive text, not a web link, executable script, or system intent.'
      };
    }
    return {
      label: 'Classification basis:',
      text: 'No deception signals detected — Standard authority formatting and valid HTTPS protocol with no homoglyphs, credentials, or redirection patterns found.'
    };
  }

  if (verdict === 'suspicious') {
    // 1. @ trick
    const isUserinfoDecoy =
      anomalies.includes('userinfo_decoy') ||
      rules.some((r) => r.id === 'authority-routing-trap') ||
      (parts?.userinfo && parts?.userinfo.includes('.'));
    if (isUserinfoDecoy) {
      const host = parts?.host || '';
      return {
        label: "Why it's flagged as Suspicious:",
        text: `Authority Routing Decoy — The link is attempting to disguise its destination. The text before '@' impersonates a domain, but the browser will actually connect to the real host '${host}'.`
      };
    }

    // 2. Lookalike / Homoglyph
    const isLookalike =
      anomalies.includes('homoglyph_cyrillic') ||
      anomalies.includes('homoglyph_greek') ||
      anomalies.includes('lookalike_domain') ||
      rules.some((r) => r.id === 'character-substitution' || r.id === 'mixed-script-detection');
    if (isLookalike) {
      const lookalikeRule = rules.find((r) => r.id === 'character-substitution' || r.id === 'mixed-script-detection');
      let targetDomain = '';
      if (lookalikeRule) {
        const match =
          lookalikeRule.reason.match(/imitates\s+([^.\s]+(?:\.[^.\s]+)+)/i) ||
          lookalikeRule.reason.match(/protected domain\s+([^.\s]+(?:\.[^.\s]+)+)/i);
        if (match) {
          targetDomain = match[1].replace(/[.,;:)]+$/, '');
        }
      }
      if (!targetDomain) {
        targetDomain = 'campus.example';
      }
      return {
        label: "Why it's flagged as Suspicious:",
        text: `Domain Impersonation / Homoglyph — The domain uses visually deceptive characters to imitate '${targetDomain}', misleading users into trusting a spoofed destination.`
      };
    }

    // 3. Raw IP
    const isRawIp =
      anomalies.includes('raw_ip_host') ||
      anomalies.includes('obfuscated_ip') ||
      rules.some((r) => r.id === 'ip-host-detection' || r.id === 'obfuscated-ip-host');
    if (isRawIp) {
      const ip = parts?.host || '';
      return {
        label: "Why it's flagged as Suspicious:",
        text: `Direct IP Authority — The link uses a raw unmapped IP address (${ip}) rather than an authenticated domain name, commonly used to bypass domain-based security filters.`
      };
    }

    // 4. Executable Data Scheme
    if (anomalies.includes('executable_data') || rules.some((r) => r.id === 'dangerous-scheme-data-html')) {
      return {
        label: "Why it's flagged as Suspicious:",
        text: 'Data URI Scheme — Encodes inline executable HTML or script content directly inside the link.'
      };
    }

    // 5. Dangerous Scheme
    const isDangerousScheme =
      anomalies.includes('dangerous_scheme') ||
      rules.some((r) => r.id?.startsWith('dangerous-scheme'));
    if (isDangerousScheme) {
      const scheme = (parts?.protocol || '').replace(/[:/]+$/, '');
      return {
        label: "Why it's flagged as Suspicious:",
        text: `Executable Scheme — Protocol '${scheme}:' can run scripts or render malicious code locally.`
      };
    }

    // 6. Malformed
    const isMalformed =
      anomalies.includes('malformed_uri_syntax') ||
      rules.some((r) => r.id === 'malformed-link');
    if (isMalformed) {
      return {
        label: "Why it's flagged as Suspicious:",
        text: 'Malformed Structure — The link syntax is invalid or corrupted, preventing safe destination parsing.'
      };
    }

    // Fallback for other suspicious triggers
    const firstSuspiciousRule = rules.find((r) => r.severity?.toLowerCase() === 'suspicious');
    return {
      label: "Why it's flagged as Suspicious:",
      text: firstSuspiciousRule?.reason || 'Clear structural deception detected in URL syntax.'
    };
  }

  if (verdict === 'review') {
    // 1. Non-Latin Script Domain
    if (anomalies.includes('non_latin_script') || rules.some((r) => r.id === 'non-latin-script')) {
      return {
        label: 'Why review is required:',
        text: 'Internationalized Domain Name — Uses full non-Latin script. Cannot verify authority against Latin-alphabet targets offline.'
      };
    }

    // 2. Excessive input length
    if (anomalies.includes('excessive_length') || rules.some((r) => r.id === 'excessive-length')) {
      return {
        label: 'Why review is required:',
        text: 'Oversized Input — Link length exceeds standard URL limits (2048 characters). Truncated to prevent regex resource exhaustion.'
      };
    }

    // 3. Multiple Targets Pasted
    if (anomalies.includes('multiple_targets') || rules.some((r) => r.id === 'multiple-targets')) {
      return {
        label: 'Why review is required:',
        text: 'Multiple destinations detected — Link Sentinel inspects one link at a time. Please test links individually.'
      };
    }

    // 4. Unrecognized Input Structure
    if (anomalies.includes('unrecognized_input') || rules.some((r) => r.id === 'unrecognized-input')) {
      return {
        label: 'Why review is required:',
        text: 'Unrecognized structure — Input does not match a valid URL, network intent, or recognized barcode format.'
      };
    }

    // 5. URL Shortener
    const isShortener =
      anomalies.includes('url_shortener') ||
      rules.some((r) => r.id === 'destination-obfuscation');
    if (isShortener) {
      return {
        label: 'Why review is required:',
        text: 'Hidden Destination — Shortened links conceal the real target host and cannot be resolved safely in an offline environment without outbound network requests.'
      };
    }

    // 6. Private IP
    const isPrivateIp =
      anomalies.includes('private_ip_host') ||
      rules.some((r) => r.id === 'private-ip-host');
    if (isPrivateIp) {
      const ip = parts?.host || '';
      return {
        label: 'Why review is required:',
        text: `Internal Network Target — The address belongs to a private RFC 1918 subnet (${ip}). It is only reachable within an internal network or local hardware.`
      };
    }

    // 7. Non-Web Scheme
    const isNonWebScheme =
      anomalies.includes('local_file_scheme') ||
      anomalies.includes('payment_intent_scheme') ||
      anomalies.includes('mail_handler_scheme') ||
      anomalies.includes('data_scheme') ||
      rules.some((r) =>
        ['local-file-scheme', 'payment-intent-scheme', 'mail-handler-scheme', 'data-scheme'].includes(r.id)
      );
    if (isNonWebScheme) {
      const scheme = (parts?.protocol || '').replace(/[:/]+$/, '');
      return {
        label: 'Why review is required:',
        text: `External Application Handler — Scheme '${scheme}:' triggers an external desktop or mobile application.`
      };
    }

    // 8. Wi-Fi Config
    if (rules.some((r) => r.id === 'wifi-config-payload') || arg?.payloadType === 'WIFI') {
      return {
        label: 'Why review is required:',
        text: 'Local Network Configuration — Connecting to unverified or open Wi-Fi access points can expose traffic to interception.'
      };
    }

    // Fallback for other review triggers
    const firstReviewRule = rules.find((r) => r.severity?.toLowerCase() === 'review');
    return {
      label: 'Why review is required:',
      text: firstReviewRule?.reason || 'Review needed: this link destination cannot be fully verified offline.'
    };
  }

  return { label: '', text: '' };
}

export default function ResultPanel({ result }) {
  if (!result) return null;

  const { verdict, parts, anomalies = [], rules = [], passedRules = [] } = result;

  // Determine tag for banner
  let tag = 'ANALYSIS';
  if (result.tag) {
    tag = result.tag;
  } else if (result.payloadType === 'UPI') {
    tag = 'UPI PAYMENT';
  } else if (result.payloadType === 'WIFI') {
    tag = 'WI-FI CONFIG';
  } else if (result.payloadType === 'TEXT') {
    tag = 'PLAIN TEXT';
  } else if (anomalies.includes('executable_data')) {
    tag = 'EXECUTABLE DATA';
  } else if (anomalies.includes('non_latin_script')) {
    tag = 'NON-LATIN SCRIPT';
  } else if (anomalies.includes('excessive_length')) {
    tag = 'EXCESSIVE LENGTH';
  } else if (anomalies.includes('multiple_targets')) {
    tag = 'MULTIPLE TARGETS';
  } else if (anomalies.includes('unrecognized_input')) {
    tag = 'UNRECOGNIZED INPUT';
  } else if (verdict === 'safe') {
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

  const primaryReason = result.primaryReason || getPrimaryReason({ verdict, parts, anomalies, rules });
  const summary = getVerdictSummary({ verdict, parts, anomalies, rules });

  return (
    <div className="flex flex-col gap-5 scroll-mt-20 sm:scroll-mt-24" aria-live="polite">
      {/* 1. Verdict Banner */}
      <VerdictBanner verdict={verdict} tag={tag} primaryReason={primaryReason} summary={summary} />

      {/* 2. URL Anatomy Breakdown or Non-Web Payload Card */}
      {result.payloadType === 'UPI' ? (
        <UpiPayloadCard data={result.data} anomalies={anomalies} />
      ) : result.payloadType === 'WIFI' ? (
        <WifiPayloadCard data={result.data} anomalies={anomalies} />
      ) : result.payloadType === 'TEXT' ? (
        <TextPayloadCard data={result.data} />
      ) : (
        <UrlTokens parts={parts} anomalies={anomalies} verdict={verdict} hasLookalikeDiff={Boolean(result?.lookalikeDiff)} />
      )}

      {/* Look-alike Character Comparison */}
      <LookalikeDiffCard diff={result?.lookalikeDiff} />

      {/* 3. Explainable Rule Breakdown */}
      <ReasonCard rules={rules} passedRules={passedRules} />
    </div>
  );
}
