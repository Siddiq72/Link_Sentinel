/**
 * Mock data for Link Sentinel UI preview & testing.
 * Conforms strictly to the data contract:
 * {
 *   input: string,
 *   verdict: "safe" | "review" | "suspicious",
 *   parts: { protocol, userinfo, host, registrableDomain, port, path, query },
 *   anomalies: string[],
 *   rules: [{ id, name, severity: "suspicious" | "review" | "note", reason }],
 *   passedRules?: string[]
 * }
 * 
 * Uses only reserved .example domains and documentation IPs (192.0.2.x).
 */

export const MOCK_RESULTS = {
  ordinary: {
    input: "https://campus.example/notices/lab-3",
    verdict: "safe",
    parts: {
      protocol: "https://",
      userinfo: "",
      host: "campus.example",
      registrableDomain: "campus.example",
      port: "",
      path: "/notices/lab-3",
      query: ""
    },
    anomalies: [],
    rules: [
      {
        id: "standard-route",
        name: "Standard Institutional Route",
        severity: "note",
        reason: "Valid HTTPS connection directly to standard institutional domain."
      }
    ],
    passedRules: [
      "No unescaped authority credential spoofing",
      "Zero Unicode or Cyrillic homoglyph characters",
      "Transport Layer Security declared (HTTPS)",
      "Standard default port 443 utilized",
      "No obfuscated path or parameter structures"
    ]
  },

  atTrick: {
    input: "https://campus.example@other.example/login",
    verdict: "suspicious",
    parts: {
      protocol: "https://",
      userinfo: "campus.example@",
      host: "other.example",
      registrableDomain: "other.example",
      port: "",
      path: "/login",
      query: ""
    },
    anomalies: ["userinfo_decoy"],
    rules: [
      {
        id: "authority-routing-trap",
        name: "Authority Routing Trap",
        severity: "suspicious",
        reason: "Flagged: the text before @ looks like a website, but the real host is other.example."
      }
    ],
    passedRules: [
      "Zero Unicode or Cyrillic homoglyph characters",
      "Transport Layer Security declared (HTTPS)",
      "Standard default port 443 utilized"
    ]
  },

  lookalike: {
    input: "https://сampus.example/login", // first letter is Cyrillic 'с' (U+0441)
    verdict: "suspicious",
    parts: {
      protocol: "https://",
      userinfo: "",
      host: "сampus.example",
      registrableDomain: "сampus.example (Punycode: xn--mpus-43d.example)",
      port: "",
      path: "/login",
      query: ""
    },
    anomalies: ["homoglyph_cyrillic"],
    rules: [
      {
        id: "character-substitution",
        name: "Character Substitution",
        severity: "suspicious",
        reason: "Flagged: this domain uses a look-alike character and imitates campus.example."
      }
    ],
    passedRules: [
      "No unescaped authority credential spoofing",
      "Transport Layer Security declared (HTTPS)",
      "Standard default port 443 utilized"
    ]
  },

  ipAddress: {
    input: "http://192.0.2.45/signin",
    verdict: "suspicious",
    parts: {
      protocol: "http://",
      userinfo: "",
      host: "192.0.2.45",
      registrableDomain: "192.0.2.45 (Raw IP Authority)",
      port: "",
      path: "/signin",
      query: ""
    },
    anomalies: ["raw_ip_host", "insecure_http"],
    rules: [
      {
        id: "ip-host-detection",
        name: "Direct IP Address Authority",
        severity: "suspicious",
        reason: "Flagged: host is an unmapped numerical IP address instead of a verified domain name."
      },
      {
        id: "insecure-scheme",
        name: "Unencrypted Protocol",
        severity: "review",
        reason: "Connection uses unencrypted HTTP protocol; credentials transmitted in cleartext."
      }
    ],
    passedRules: [
      "No unescaped authority credential spoofing",
      "Zero Unicode homoglyph characters"
    ]
  },

  shortener: {
    input: "https://bit.ly/3abcXYZ",
    verdict: "review",
    parts: {
      protocol: "https://",
      userinfo: "",
      host: "bit.ly",
      registrableDomain: "bit.ly",
      port: "",
      path: "/3abcXYZ",
      query: ""
    },
    anomalies: ["url_shortener"],
    rules: [
      {
        id: "destination-obfuscation",
        name: "Destination Obfuscation",
        severity: "review",
        reason: "Shortened link: the real destination is hidden and cannot be checked offline."
      }
    ],
    passedRules: [
      "No unescaped authority credential spoofing",
      "Zero Unicode or Cyrillic homoglyph characters",
      "Transport Layer Security declared (HTTPS)"
    ]
  },

  complexSafe: {
    input: "https://portal.campus.example:8443/forms/submit?id=42&contact=lab@campus.example",
    verdict: "safe",
    parts: {
      protocol: "https://",
      userinfo: "",
      host: "portal.campus.example",
      registrableDomain: "campus.example",
      port: ":8443",
      path: "/forms/submit",
      query: "?id=42&contact=lab@campus.example"
    },
    anomalies: [],
    rules: [
      {
        id: "parameter-context-check",
        name: "Parameter Context Check",
        severity: "note",
        reason: "The @ appears in the query, so it is not a login trick."
      }
    ],
    passedRules: [
      "No unescaped authority credential spoofing",
      "Zero Unicode or Cyrillic homoglyph characters",
      "Transport Layer Security declared (HTTPS)",
      "Explicit non-standard port 8443 recognized",
      "Standard uncompressed query argument structure"
    ]
  }
};
