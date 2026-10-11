/**
 * Cyrillic and Greek homoglyph mappings to visual Latin equivalents.
 * Derived from Unicode Technical Report #39 (Unicode Security Mechanisms).
 */

export const CONFUSABLES = {
  // Cyrillic Lowercase to Latin
  '\u0430': 'a', // Cyrillic Small Letter A
  '\u0441': 'c', // Cyrillic Small Letter Es
  '\u0435': 'e', // Cyrillic Small Letter Ie
  '\u043E': 'o', // Cyrillic Small Letter O
  '\u0440': 'p', // Cyrillic Small Letter Er
  '\u0445': 'x', // Cyrillic Small Letter Ha
  '\u0443': 'y', // Cyrillic Small Letter U
  '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
  '\u0458': 'j', // Cyrillic Small Letter Je
  '\u0455': 's', // Cyrillic Small Letter Dze
  '\u0432': 'b', // Cyrillic Small Letter Ve
  '\u043A': 'k', // Cyrillic Small Letter Ka
  '\u043C': 'm', // Cyrillic Small Letter Em
  '\u043D': 'h', // Cyrillic Small Letter En
  '\u0442': 't', // Cyrillic Small Letter Te
  '\u045D': 'e', // Cyrillic Small Letter Ie with Grave
  '\u0451': 'e', // Cyrillic Small Letter Io
  '\u0501': 'd', // Cyrillic Small Letter Komi De
  '\u051B': 'q', // Cyrillic Small Letter Qa
  '\u051D': 'w', // Cyrillic Small Letter We

  // Cyrillic Uppercase to Latin
  '\u0410': 'a', // Cyrillic Capital Letter A
  '\u0412': 'b', // Cyrillic Capital Letter Ve
  '\u0421': 'c', // Cyrillic Capital Letter Es
  '\u0415': 'e', // Cyrillic Capital Letter Ie
  '\u041D': 'h', // Cyrillic Capital Letter En
  '\u0406': 'i', // Cyrillic Capital Letter Byelorussian-Ukrainian I
  '\u0408': 'j', // Cyrillic Capital Letter Je
  '\u041A': 'k', // Cyrillic Capital Letter Ka
  '\u041C': 'm', // Cyrillic Capital Letter Em
  '\u041E': 'o', // Cyrillic Capital Letter O
  '\u0420': 'p', // Cyrillic Capital Letter Er
  '\u0421': 's', // Cyrillic Capital Letter Es
  '\u0422': 't', // Cyrillic Capital Letter Te
  '\u0425': 'x', // Cyrillic Capital Letter Ha
  '\u0423': 'y', // Cyrillic Capital Letter U
  '\u0401': 'e', // Cyrillic Capital Letter Io

  // Greek Lowercase to Latin
  '\u03B1': 'a', // Greek Small Letter Alpha
  '\u03B2': 'b', // Greek Small Letter Beta
  '\u03B5': 'e', // Greek Small Letter Epsilon
  '\u03B6': 'z', // Greek Small Letter Zeta
  '\u03B7': 'n', // Greek Small Letter Eta
  '\u03B9': 'i', // Greek Small Letter Iota
  '\u03BA': 'k', // Greek Small Letter Kappa
  '\u03BC': 'u', // Greek Small Letter Mu
  '\u03BD': 'v', // Greek Small Letter Nu
  '\u03BF': 'o', // Greek Small Letter Omicron
  '\u03C1': 'p', // Greek Small Letter Rho
  '\u03C4': 't', // Greek Small Letter Tau
  '\u03C5': 'y', // Greek Small Letter Upsilon
  '\u03C7': 'x', // Greek Small Letter Chi
  '\u03C9': 'w', // Greek Small Letter Omega

  // Greek Uppercase to Latin
  '\u0391': 'a', // Greek Capital Letter Alpha
  '\u0392': 'b', // Greek Capital Letter Beta
  '\u0395': 'e', // Greek Capital Letter Epsilon
  '\u0396': 'z', // Greek Capital Letter Zeta
  '\u0397': 'h', // Greek Capital Letter Eta
  '\u0399': 'i', // Greek Capital Letter Iota
  '\u039A': 'k', // Greek Capital Letter Kappa
  '\u039C': 'm', // Greek Capital Letter Mu
  '\u039D': 'n', // Greek Capital Letter Nu
  '\u039F': 'o', // Greek Capital Letter Omicron
  '\u03A1': 'p', // Greek Capital Letter Rho
  '\u03A4': 't', // Greek Capital Letter Tau
  '\u03A5': 'y', // Greek Capital Letter Upsilon
  '\u03A7': 'x', // Greek Capital Letter Chi
  '\u03A9': 'o'  // Greek Capital Letter Omega
};

/**
 * Normalizes a string by converting Cyrillic and Greek homoglyphs to their Latin skeletons.
 * 
 * @param {string} str - Raw input string (e.g. domain label).
 * @returns {string} Normalized skeleton string in lowercase.
 */
export function getSkeleton(str) {
  if (!str || typeof str !== 'string') return '';
  return [...str]
    .map((char) => CONFUSABLES[char] || char.toLowerCase())
    .join('');
}

/**
 * Checks if a string contains any Cyrillic characters.
 * @param {string} str 
 * @returns {boolean}
 */
export function hasCyrillic(str) {
  if (!str || typeof str !== 'string') return false;
  return /[\u0400-\u04FF\u0500-\u052F]/.test(str);
}

/**
 * Checks if a string contains any Greek characters.
 * @param {string} str 
 * @returns {boolean}
 */
export function hasGreek(str) {
  if (!str || typeof str !== 'string') return false;
  return /[\u0370-\u03FF]/.test(str);
}

/**
 * Checks if a string contains mixed Latin and non-Latin scripts (Cyrillic or Greek).
 * @param {string} str 
 * @returns {boolean}
 */
export function isMixedScript(str) {
  if (!str || typeof str !== 'string') return false;
  const hasLatinChar = /[a-zA-Z]/.test(str);
  const hasNonLatinChar = hasCyrillic(str) || hasGreek(str);
  return hasLatinChar && hasNonLatinChar;
}

export default {
  CONFUSABLES,
  getSkeleton,
  hasCyrillic,
  hasGreek,
  isMixedScript
};
