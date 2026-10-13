/**
 * Evaluates URL authority userinfo for deception traps.
 * Flags:
 * - Userinfo containing a dot ('.') as "suspicious" (authority deception trap).
 * - Userinfo without a dot as "review" (credential transmission).
 * - Ignores '@' symbols contained within query parameters or path.
 */

export function evaluateUserinfoRule(parsedContext) {
  const { url, domainInfo, hasEncodedAt, rawAuthority } = parsedContext;
  const username = url.username || '';
  const password = url.password || '';
  const userinfo = username + (password ? `:${password}` : '');
  const realHost = domainInfo?.unicodeHostname || url.hostname || '';

  const rules = [];
  const anomalies = [];

  const isDecoy = Boolean(
    (userinfo && userinfo.includes('.')) ||
    hasEncodedAt ||
    (rawAuthority && (/%2540|%40/i.test(rawAuthority) || (rawAuthority.includes('@') && rawAuthority.split('@')[0].includes('.'))))
  );

  if (isDecoy) {
    rules.push({
      id: 'authority-routing-trap',
      name: 'Authority Routing Trap',
      severity: 'suspicious',
      reason: `Flagged: the text before @ looks like a website, but the real host is ${realHost}.`
    });
    anomalies.push('userinfo_decoy');
  } else if (userinfo) {
    rules.push({
      id: 'userinfo-credentials',
      name: 'Authority Credentials',
      severity: 'review',
      reason: 'Flagged: connection authority embeds user credentials before the host.'
    });
    anomalies.push('userinfo_credentials');
  } else if (url.search && url.search.includes('@')) {
    rules.push({
      id: 'parameter-context-check',
      name: 'Parameter Context Check',
      severity: 'note',
      reason: 'The @ appears in the query, so it is not a login trick.'
    });
  }

  return { rules, anomalies };
}

export const evaluateAuthorityRule = evaluateUserinfoRule;
export default evaluateUserinfoRule;
