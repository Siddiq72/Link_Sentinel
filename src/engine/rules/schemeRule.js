/**
 * Scheme evaluation rule.
 * Flags:
 * - javascript:, vbscript:, data:text/html as "suspicious"
 * - file:, upi:, mailto: as "review"
 * - http: as "note"
 */

export function evaluateSchemeRule(parsedContext) {
  const { url, rawInput = '' } = parsedContext;
  const protocol = (url.protocol || '').toLowerCase();
  const rules = [];
  const anomalies = [];

  if (protocol === 'javascript:') {
    rules.push({
      id: 'dangerous-scheme-javascript',
      name: 'Executable Script Protocol',
      severity: 'suspicious',
      reason: 'Flagged: javascript: pseudo-protocol executes arbitrary client-side code.'
    });
    anomalies.push('dangerous_scheme');
  } else if (protocol === 'vbscript:') {
    rules.push({
      id: 'dangerous-scheme-vbscript',
      name: 'Executable Script Protocol',
      severity: 'suspicious',
      reason: 'Flagged: vbscript: pseudo-protocol executes script code.'
    });
    anomalies.push('dangerous_scheme');
  } else if (protocol === 'data:') {
    const rawLower = rawInput.toLowerCase();
    const pathnameLower = (url.pathname || '').toLowerCase();
    if (rawLower.includes('text/html') || pathnameLower.includes('text/html')) {
      rules.push({
        id: 'dangerous-scheme-data-html',
        name: 'Executable Data Scheme',
        severity: 'suspicious',
        reason: 'Flagged: data:text/html scheme embeds raw HTML/scripts capable of phishing or execution.'
      });
      anomalies.push('dangerous_scheme');
    } else {
      rules.push({
        id: 'data-scheme',
        name: 'Data URI Scheme',
        severity: 'review',
        reason: 'Flagged: data: URI embeds inline payloads without standard host origin.'
      });
      anomalies.push('data_scheme');
    }
  } else if (protocol === 'file:') {
    rules.push({
      id: 'local-file-scheme',
      name: 'Local File Protocol',
      severity: 'review',
      reason: 'Local file: protocol targets host device filesystem, not a remote web origin.'
    });
    anomalies.push('local_file_scheme');
  } else if (protocol === 'upi:') {
    rules.push({
      id: 'payment-intent-scheme',
      name: 'Payment Intent Protocol',
      severity: 'review',
      reason: 'Deep link triggers external payment application (UPI intent).'
    });
    anomalies.push('payment_intent_scheme');
  } else if (protocol === 'mailto:') {
    rules.push({
      id: 'mail-handler-scheme',
      name: 'Email Handler Protocol',
      severity: 'review',
      reason: 'Protocol opens local mail client rather than navigating to a secure webpage.'
    });
    anomalies.push('mail_handler_scheme');
  } else if (protocol === 'http:') {
    rules.push({
      id: 'insecure-scheme',
      name: 'Unencrypted Protocol',
      severity: 'note',
      reason: 'Connection uses unencrypted HTTP protocol; credentials transmitted in cleartext.'
    });
    anomalies.push('insecure_http');
  }

  return { rules, anomalies };
}

export default evaluateSchemeRule;
