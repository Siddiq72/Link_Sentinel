/**
 * NAIVE REGEX BASELINE CHECKER
 * 
 * Demonstrates the flaws of primitive pattern-matching and keyword-based
 * security heuristics typically used in legacy email filters or naive screeners.
 * 
 * Common flaws simulated:
 * - Flags ANY occurrence of "@" (falsely flagging legitimate queries like ?contact=lab@campus.example).
 * - Flags ANY numeric IP pattern (failing to distinguish private LANs from public attacks).
 * - Flags ANY non-ASCII character (failing structured confusable skeleton analysis).
 * - Flags known shortener strings as unconditionally suspicious rather than review-needed.
 * - Flags keywords like login, signin, verify, secure, bank, canteen regardless of origin.
 */

/**
 * Evaluates an input string against basic regex heuristics.
 * 
 * @param {string} rawInput - Input URL or QR string
 * @returns {{ verdict: 'suspicious' | 'safe', triggerReason: string }}
 */
export function runNaiveCheck(rawInput) {
  if (rawInput === null || rawInput === undefined || typeof rawInput !== 'string') {
    return { verdict: 'safe', triggerReason: 'Input is empty or invalid' };
  }

  const str = rawInput.trim();
  if (!str) {
    return { verdict: 'safe', triggerReason: 'Input is empty' };
  }

  // 1. Naive check: Any occurrence of "@" anywhere in the string
  if (str.includes('@')) {
    return {
      verdict: 'suspicious',
      triggerReason: "Contains '@' symbol (naive rule flags all @ characters without checking query parameter context)"
    };
  }

  // 2. Naive check: Any IPv4, IPv6, or Hex-encoded IP pattern
  if (
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(str) ||
    /0x[0-9a-fA-F]+/i.test(str) ||
    /\[?[0-9a-fA-F:]{4,}\]?/.test(str)
  ) {
    return {
      verdict: 'suspicious',
      triggerReason: 'Contains numeric IP pattern (flags all IP routing without distinguishing private RFC 1918 subnets)'
    };
  }

  // 3. Naive check: Any non-ASCII character (homoglyphs, bidi, zero-width)
  if (/[^\x00-\x7F]/.test(str)) {
    return {
      verdict: 'suspicious',
      triggerReason: 'Contains non-ASCII character (crude filter flags all international scripts without confusable diffs)'
    };
  }

  // 4. Naive check: Hardcoded shortener domains
  if (/bit\.ly|tinyurl/i.test(str)) {
    return {
      verdict: 'suspicious',
      triggerReason: 'Matches shortener domain substring (flags shorteners as attack rather than review requirement)'
    };
  }

  // 5. Naive check: Sensitive keyword patterns
  const keywordMatch = str.match(/(login|signin|verify|secure|security|bank|canteen)/i);
  if (keywordMatch) {
    return {
      verdict: 'suspicious',
      triggerReason: `Contains keyword "${keywordMatch[1]}" (flags keywords in paths or queries without origin validation)`
    };
  }

  // 6. Naive check: Dangerous pseudo-protocols
  if (/^(javascript|vbscript|data):/i.test(str)) {
    return {
      verdict: 'suspicious',
      triggerReason: 'Matches script execution protocol scheme'
    };
  }

  return {
    verdict: 'safe',
    triggerReason: 'No naive regex or keyword rule triggered'
  };
}

export default runNaiveCheck;
