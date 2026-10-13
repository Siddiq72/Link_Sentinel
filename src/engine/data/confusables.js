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

export const CONFUSABLE_METADATA = {
  // Cyrillic Lowercase to Latin
  '\u0430': { char: '\u0430', codePoint: 'U+0430', name: 'CYRILLIC SMALL LETTER A', latinMatch: 'a' },
  '\u0441': { char: '\u0441', codePoint: 'U+0441', name: 'CYRILLIC SMALL LETTER ES', latinMatch: 'c' },
  '\u0435': { char: '\u0435', codePoint: 'U+0435', name: 'CYRILLIC SMALL LETTER IE', latinMatch: 'e' },
  '\u043E': { char: '\u043E', codePoint: 'U+043E', name: 'CYRILLIC SMALL LETTER O', latinMatch: 'o' },
  '\u0440': { char: '\u0440', codePoint: 'U+0440', name: 'CYRILLIC SMALL LETTER ER', latinMatch: 'p' },
  '\u0445': { char: '\u0445', codePoint: 'U+0445', name: 'CYRILLIC SMALL LETTER HA', latinMatch: 'x' },
  '\u0443': { char: '\u0443', codePoint: 'U+0443', name: 'CYRILLIC SMALL LETTER U', latinMatch: 'y' },
  '\u0456': { char: '\u0456', codePoint: 'U+0456', name: 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I', latinMatch: 'i' },
  '\u0458': { char: '\u0458', codePoint: 'U+0458', name: 'CYRILLIC SMALL LETTER JE', latinMatch: 'j' },
  '\u0455': { char: '\u0455', codePoint: 'U+0455', name: 'CYRILLIC SMALL LETTER DZE', latinMatch: 's' },
  '\u0432': { char: '\u0432', codePoint: 'U+0432', name: 'CYRILLIC SMALL LETTER VE', latinMatch: 'b' },
  '\u043A': { char: '\u043A', codePoint: 'U+043A', name: 'CYRILLIC SMALL LETTER KA', latinMatch: 'k' },
  '\u043C': { char: '\u043C', codePoint: 'U+043C', name: 'CYRILLIC SMALL LETTER EM', latinMatch: 'm' },
  '\u043D': { char: '\u043D', codePoint: 'U+043D', name: 'CYRILLIC SMALL LETTER EN', latinMatch: 'h' },
  '\u0442': { char: '\u0442', codePoint: 'U+0442', name: 'CYRILLIC SMALL LETTER TE', latinMatch: 't' },
  '\u045D': { char: '\u045D', codePoint: 'U+045D', name: 'CYRILLIC SMALL LETTER IE WITH GRAVE', latinMatch: 'e' },
  '\u0451': { char: '\u0451', codePoint: 'U+0451', name: 'CYRILLIC SMALL LETTER IO', latinMatch: 'e' },
  '\u0501': { char: '\u0501', codePoint: 'U+0501', name: 'CYRILLIC SMALL LETTER KOMI DE', latinMatch: 'd' },
  '\u051B': { char: '\u051B', codePoint: 'U+051B', name: 'CYRILLIC SMALL LETTER QA', latinMatch: 'q' },
  '\u051D': { char: '\u051D', codePoint: 'U+051D', name: 'CYRILLIC SMALL LETTER WE', latinMatch: 'w' },

  // Cyrillic Uppercase to Latin
  '\u0410': { char: '\u0410', codePoint: 'U+0410', name: 'CYRILLIC CAPITAL LETTER A', latinMatch: 'a' },
  '\u0412': { char: '\u0412', codePoint: 'U+0412', name: 'CYRILLIC CAPITAL LETTER VE', latinMatch: 'b' },
  '\u0421': { char: '\u0421', codePoint: 'U+0421', name: 'CYRILLIC CAPITAL LETTER ES', latinMatch: 'c' },
  '\u0415': { char: '\u0415', codePoint: 'U+0415', name: 'CYRILLIC CAPITAL LETTER IE', latinMatch: 'e' },
  '\u041D': { char: '\u041D', codePoint: 'U+041D', name: 'CYRILLIC CAPITAL LETTER EN', latinMatch: 'h' },
  '\u0406': { char: '\u0406', codePoint: 'U+0406', name: 'CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I', latinMatch: 'i' },
  '\u0408': { char: '\u0408', codePoint: 'U+0408', name: 'CYRILLIC CAPITAL LETTER JE', latinMatch: 'j' },
  '\u041A': { char: '\u041A', codePoint: 'U+041A', name: 'CYRILLIC CAPITAL LETTER KA', latinMatch: 'k' },
  '\u041C': { char: '\u041C', codePoint: 'U+041C', name: 'CYRILLIC CAPITAL LETTER EM', latinMatch: 'm' },
  '\u041E': { char: '\u041E', codePoint: 'U+041E', name: 'CYRILLIC CAPITAL LETTER O', latinMatch: 'o' },
  '\u0420': { char: '\u0420', codePoint: 'U+0420', name: 'CYRILLIC CAPITAL LETTER ER', latinMatch: 'p' },
  '\u0422': { char: '\u0422', codePoint: 'U+0422', name: 'CYRILLIC CAPITAL LETTER TE', latinMatch: 't' },
  '\u0425': { char: '\u0425', codePoint: 'U+0425', name: 'CYRILLIC CAPITAL LETTER HA', latinMatch: 'x' },
  '\u0423': { char: '\u0423', codePoint: 'U+0423', name: 'CYRILLIC CAPITAL LETTER U', latinMatch: 'y' },
  '\u0401': { char: '\u0401', codePoint: 'U+0401', name: 'CYRILLIC CAPITAL LETTER IO', latinMatch: 'e' },

  // Greek Lowercase to Latin
  '\u03B1': { char: '\u03B1', codePoint: 'U+03B1', name: 'GREEK SMALL LETTER ALPHA', latinMatch: 'a' },
  '\u03B2': { char: '\u03B2', codePoint: 'U+03B2', name: 'GREEK SMALL LETTER BETA', latinMatch: 'b' },
  '\u03B5': { char: '\u03B5', codePoint: 'U+03B5', name: 'GREEK SMALL LETTER EPSILON', latinMatch: 'e' },
  '\u03B6': { char: '\u03B6', codePoint: 'U+03B6', name: 'GREEK SMALL LETTER ZETA', latinMatch: 'z' },
  '\u03B7': { char: '\u03B7', codePoint: 'U+03B7', name: 'GREEK SMALL LETTER ETA', latinMatch: 'n' },
  '\u03B9': { char: '\u03B9', codePoint: 'U+03B9', name: 'GREEK SMALL LETTER IOTA', latinMatch: 'i' },
  '\u03BA': { char: '\u03BA', codePoint: 'U+03BA', name: 'GREEK SMALL LETTER KAPPA', latinMatch: 'k' },
  '\u03BC': { char: '\u03BC', codePoint: 'U+03BC', name: 'GREEK SMALL LETTER MU', latinMatch: 'u' },
  '\u03BD': { char: '\u03BD', codePoint: 'U+03BD', name: 'GREEK SMALL LETTER NU', latinMatch: 'v' },
  '\u03BF': { char: '\u03BF', codePoint: 'U+03BF', name: 'GREEK SMALL LETTER OMICRON', latinMatch: 'o' },
  '\u03C1': { char: '\u03C1', codePoint: 'U+03C1', name: 'GREEK SMALL LETTER RHO', latinMatch: 'p' },
  '\u03C4': { char: '\u03C4', codePoint: 'U+03C4', name: 'GREEK SMALL LETTER TAU', latinMatch: 't' },
  '\u03C5': { char: '\u03C5', codePoint: 'U+03C5', name: 'GREEK SMALL LETTER UPSILON', latinMatch: 'y' },
  '\u03C7': { char: '\u03C7', codePoint: 'U+03C7', name: 'GREEK SMALL LETTER CHI', latinMatch: 'x' },
  '\u03C9': { char: '\u03C9', codePoint: 'U+03C9', name: 'GREEK SMALL LETTER OMEGA', latinMatch: 'w' },

  // Greek Uppercase to Latin
  '\u0391': { char: '\u0391', codePoint: 'U+0391', name: 'GREEK CAPITAL LETTER ALPHA', latinMatch: 'a' },
  '\u0392': { char: '\u0392', codePoint: 'U+0392', name: 'GREEK CAPITAL LETTER BETA', latinMatch: 'b' },
  '\u0395': { char: '\u0395', codePoint: 'U+0395', name: 'GREEK CAPITAL LETTER EPSILON', latinMatch: 'e' },
  '\u0396': { char: '\u0396', codePoint: 'U+0396', name: 'GREEK CAPITAL LETTER ZETA', latinMatch: 'z' },
  '\u0397': { char: '\u0397', codePoint: 'U+0397', name: 'GREEK CAPITAL LETTER ETA', latinMatch: 'h' },
  '\u0399': { char: '\u0399', codePoint: 'U+0399', name: 'GREEK CAPITAL LETTER IOTA', latinMatch: 'i' },
  '\u039A': { char: '\u039A', codePoint: 'U+039A', name: 'GREEK CAPITAL LETTER KAPPA', latinMatch: 'k' },
  '\u039C': { char: '\u039C', codePoint: 'U+039C', name: 'GREEK CAPITAL LETTER MU', latinMatch: 'm' },
  '\u039D': { char: '\u039D', codePoint: 'U+039D', name: 'GREEK CAPITAL LETTER NU', latinMatch: 'n' },
  '\u039F': { char: '\u039F', codePoint: 'U+039F', name: 'GREEK CAPITAL LETTER OMICRON', latinMatch: 'o' },
  '\u03A1': { char: '\u03A1', codePoint: 'U+03A1', name: 'GREEK CAPITAL LETTER RHO', latinMatch: 'p' },
  '\u03A4': { char: '\u03A4', codePoint: 'U+03A4', name: 'GREEK CAPITAL LETTER TAU', latinMatch: 't' },
  '\u03A5': { char: '\u03A5', codePoint: 'U+03A5', name: 'GREEK CAPITAL LETTER UPSILON', latinMatch: 'y' },
  '\u03A7': { char: '\u03A7', codePoint: 'U+03A7', name: 'GREEK CAPITAL LETTER CHI', latinMatch: 'x' },
  '\u03A9': { char: '\u03A9', codePoint: 'U+03A9', name: 'GREEK CAPITAL LETTER OMEGA', latinMatch: 'o' }
};

/**
 * Compares an analyzed fake host against a genuine target domain and produces
 * character-by-character tokens with Unicode confusable metadata and punycode.
 *
 * @param {string} fakeHost - Spoofed hostname (e.g. "сampus.example").
 * @param {string} genuineDomain - Authentic target domain (e.g. "campus.example").
 * @returns {object} Diff analysis object.
 */
export function computeLookalikeDiff(fakeHost, genuineDomain) {
  if (!fakeHost || !genuineDomain) return null;

  let parsedPunycode = '';
  try {
    parsedPunycode = new URL('http://' + fakeHost).hostname;
  } catch {
    parsedPunycode = fakeHost.toLowerCase();
  }

  const fakeChars = [...fakeHost];

  const characters = fakeChars.map((char) => {
    const isConfusable = Boolean(CONFUSABLES[char]) || char.charCodeAt(0) > 127;
    const skeletonChar = CONFUSABLES[char] || char.toLowerCase();

    if (isConfusable) {
      const meta = CONFUSABLE_METADATA[char] || {
        char,
        codePoint: 'U+' + char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
        name: `NON-ASCII CHARACTER ${char}`,
        latinMatch: skeletonChar
      };
      return {
        char,
        isConfusable: true,
        metadata: meta
      };
    }

    return {
      char,
      isConfusable: false,
      metadata: null
    };
  });

  return {
    genuineDomain,
    fakeHost,
    punycode: parsedPunycode,
    characters
  };
}

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
  CONFUSABLE_METADATA,
  computeLookalikeDiff,
  getSkeleton,
  hasCyrillic,
  hasGreek,
  isMixedScript
};
