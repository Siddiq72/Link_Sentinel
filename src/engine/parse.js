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
    throw new Error('Please enter a valid link.');
  }

  const hasZeroWidth = ZERO_WIDTH_REGEX.test(rawInput);
  const stripped = rawInput.replace(ZERO_WIDTH_REGEX, '');
  const normalized = stripped.trim();

  if (!normalized) {
    throw new Error('Please enter a valid link.');
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

  let url;
  try {
    url = new URL(workingUrl);
  } catch {
    throw new Error('Please enter a valid link.');
  }

  return {
    url,
    rawInput,
    normalizedInput: normalized,
    hasBidi,
    hasBackslash,
    hasZeroWidth,
    prependedHttps
  };
}

export default parseInput;
