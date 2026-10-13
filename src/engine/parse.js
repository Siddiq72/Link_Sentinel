/**
 * Defensive URL input parser.
 * Handles zero-width stripping, bidi overrides detection, whitespace normalization,
 * scheme completion, and WHATWG URL object creation.
 */

const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF]/g;
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/;

/**
 * Parses and sanitizes a raw link string.
 *
 * @param {string} rawInput - The user-supplied URL input.
 * @returns {object} Normalized parse object containing the WHATWG URL instance and detection flags.
 * @throws {Error} If input is empty, non-string, or invalid URL format.
 */
export function parseInput(rawInput) {
  if (rawInput === null || rawInput === undefined || typeof rawInput !== 'string') {
    throw new Error('Please enter a valid link. Please enter a link or scan a QR code to inspect.');
  }

  const hasZeroWidth = ZERO_WIDTH_REGEX.test(rawInput);
  const stripped = rawInput.replace(ZERO_WIDTH_REGEX, '');
  const normalized = stripped.trim();

  if (!normalized) {
    throw new Error('Please enter a valid link. Please enter a link or scan a QR code to inspect.');
  }

  const hasBidi = BIDI_REGEX.test(normalized);
  const hasBackslash = normalized.includes('\\');

  let workingUrl = normalized;
  let prependedHttps = false;

  // Schemes that do not require '//'
  const isOpaqueOrKnownScheme = /^(javascript|vbscript|data|mailto|tel|sms|file):/i.test(workingUrl);
  // Standard hierarchical scheme with ://
  const hasHierarchicalScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(workingUrl);

  if (!isOpaqueOrKnownScheme && !hasHierarchicalScheme) {
    if (workingUrl.startsWith('//')) {
      workingUrl = 'https:' + workingUrl;
    } else {
      workingUrl = 'https://' + workingUrl;
    }
    prependedHttps = true;
  }

  // Pre-normalize authority: decode %40/%2540 and strip trailing root dots on host
  let hasEncodedAt = false;
  let rawAuthority = '';
  const authMatch = workingUrl.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/?#]+)(.*)$/);
  if (authMatch) {
    rawAuthority = authMatch[2];
    let hostPortPart = rawAuthority;

    if (/%2540|%40/i.test(rawAuthority)) {
      hasEncodedAt = true;
      hostPortPart = hostPortPart.replace(/%2540/gi, '@').replace(/%40/gi, '@');
    }

    const atIdx = hostPortPart.lastIndexOf('@');
    const userinfoPart = atIdx !== -1 ? hostPortPart.slice(0, atIdx + 1) : '';
    let hostPart = atIdx !== -1 ? hostPortPart.slice(atIdx + 1) : hostPortPart;
    hostPart = hostPart.replace(/\.(:\d+)?$/, (m, p) => p || '');

    const normalizedAuth = userinfoPart + hostPart;
    workingUrl = authMatch[1] + normalizedAuth + authMatch[3];
  }

  let url;
  try {
    url = new URL(workingUrl);
  } catch {
    const error = new Error('Malformed URI structure');
    error.isMalformed = true;
    error.rawInput = rawInput;
    error.workingUrl = workingUrl;
    throw error;
  }

  return {
    url,
    rawInput,
    normalizedInput: normalized,
    hasBidi,
    hasBackslash,
    hasZeroWidth,
    hasEncodedAt,
    rawAuthority,
    prependedHttps
  };
}

export default parseInput;
