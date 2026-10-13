/**
 * LINK SENTINEL - EVIDENCE & REGRESSION BENCHMARK CORPUS
 * 
 * Curated 40-item offline regression corpus for evaluating Link Sentinel's
 * deterministic structural analysis against naive regex/keyword filtering.
 * 
 * Categories:
 * - Benign Complex (12): Legitimate institutional links with tricky features (@ in query, ports, deep subdomains).
 * - Structural Attack (10): Active deception techniques (userinfo traps, homoglyphs, IP hosts, script schemes).
 * - Review Class (8): Links requiring manual or contextual verification (shorteners, private RFC 1918 IPs, protocols).
 * - Non-URL Payload (6): Barcode intents (UPI payment parameters, Wi-Fi MECARD, plain text).
 * - Known Limits (4): Transparently documented system boundaries where structural inspection yields to reputation feeds.
 */

export const BENCHMARK_CORPUS = [
  // --- 1. BENIGN COMPLEX LINKS (12 items) ---
  {
    id: 'benign-query-at-symbol',
    input: 'https://portal.campus.example:8443/forms?contact=lab@campus.example',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Legitimate @ in Query Parameter',
    explanation: 'Contains "@" inside query parameter string, not URL authority. Browser routes to legitimate host, not decoy.'
  },
  {
    id: 'benign-ordinary-institutional',
    input: 'https://campus.example/notices/lab-3',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Standard Institutional HTTPS Notice',
    explanation: 'Standard HTTPS link using authenticated institutional domain and clean hierarchical path.'
  },
  {
    id: 'benign-deep-subdomains',
    input: 'https://sub3.sub2.sub1.campus.example/dashboard',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Deep Multi-Level Subdomains',
    explanation: 'Multi-level nested subdomains correctly resolved to genuine registrable domain campus.example.'
  },
  {
    id: 'benign-custom-high-port',
    input: 'https://library.campus.example:8080/catalog',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Explicit Alternate Port 8080',
    explanation: 'Uses explicit port 8080 with valid HTTPS scheme and legitimate host origin.'
  },
  {
    id: 'benign-deep-path-hierarchy',
    input: 'https://campus.example/dept/cs/courses/2026/spring/syllabus',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Deep Academic Path Hierarchy',
    explanation: 'Lengthy academic course catalog path without obfuscation characters or backslashes.'
  },
  {
    id: 'benign-multiple-search-queries',
    input: 'https://search.campus.example/results?q=security+seminar&filter=2026',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Search Query with Keyword "security"',
    explanation: 'Query contains sensitive keyword "security" as search parameter value, which naive regexes falsely flag.'
  },
  {
    id: 'benign-url-fragment-anchor',
    input: 'https://campus.example/policies#section-4',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Document Anchor Fragment (#)',
    explanation: 'Valid fragment identifier routed purely client-side by browser rendering engine.'
  },
  {
    id: 'benign-oauth-callback-url',
    input: 'https://campus.example/api/v1/auth/callback?code=abc123xyz&state=ok',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'API Authentication Callback Parameters',
    explanation: 'Standard OAuth callback parameters without authority tampering or homoglyphs.'
  },
  {
    id: 'benign-developer-docs',
    input: 'https://docs.campus.example/guide/getting-started',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Institutional Documentation Guide',
    explanation: 'Subdomain docs route on campus.example with clean alphanumeric slugs.'
  },
  {
    id: 'benign-support-email-param',
    input: 'https://campus.example/support?email=student@alumni.campus.example',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Support Form with Student Email Value',
    explanation: 'Query parameter email includes @ without posing authority routing danger.'
  },
  {
    id: 'benign-static-pdf-document',
    input: 'https://campus.example/archive/reports/annual-audit-2025-final.pdf',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Static PDF Document File Route',
    explanation: 'Direct link to static archive document with standard HTTPS protocol.'
  },
  {
    id: 'benign-complex-schedule-matrix',
    input: 'https://campus.example/schedule?term=fall&session=morning&room=aud-1',
    expectedVerdict: 'safe',
    category: 'Benign Complex',
    label: 'Multi-Parameter Class Schedule',
    explanation: 'Structured institutional database query parameters.'
  },

  // --- 2. STRUCTURAL ATTACK LINKS (10 items) ---
  {
    id: 'attack-userinfo-routing-decoy',
    input: 'https://campus.example@other.example/login',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Authority Routing Trap (@ Decoy)',
    explanation: 'Disguises destination by placing trusted domain in userinfo before @; browser actually navigates to other.example.'
  },
  {
    id: 'attack-cyrillic-homoglyph-substitution',
    input: 'https://\u0441ampus.example/login',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Cyrillic Homoglyph Domain Spoof',
    explanation: 'First character is Cyrillic small letter "с" (U+0441), visually mimicking Latin "c" to impersonate campus.example.'
  },
  {
    id: 'attack-greek-homoglyph-substitution',
    input: 'https://c\u03BFmpus.example/login',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Greek Homoglyph Domain Spoof',
    explanation: 'Contains Greek small letter omicron (U+03BF) mimicking Latin "o" within target domain name.'
  },
  {
    id: 'attack-raw-public-ip-host',
    input: 'http://192.0.2.45/signin',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Raw Public IP Authority Host',
    explanation: 'Uses unmapped public IP address instead of authenticated domain name to evade reputation blocklists.'
  },
  {
    id: 'attack-obfuscated-hex-ip',
    input: 'http://0x7f000001/malware',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Hexadecimal Encoded IP Authority',
    explanation: 'Uses hexadecimal integer encoding (0x7f000001) to disguise destination IP from naive string filters.'
  },
  {
    id: 'attack-executable-javascript-scheme',
    input: 'javascript:alert(document.cookie)',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Executable JavaScript Pseudo-Protocol',
    explanation: 'Protocol executes client-side script code directly in local browser context without network navigation.'
  },
  {
    id: 'attack-executable-vbscript-scheme',
    input: 'vbscript:msgbox(1)',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Executable VBScript Protocol',
    explanation: 'Legacy executable script scheme capable of running local instructions in compatible engines.'
  },
  {
    id: 'attack-executable-data-html-scheme',
    input: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Inline Executable Data HTML Scheme',
    explanation: 'Data URI embeds raw HTML and script payloads directly in link string without remote origin.'
  },
  {
    id: 'attack-bidi-text-reversal-override',
    input: 'https://campus.example/\u202Ereversed',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Unicode Bi-Directional Override',
    explanation: 'Embeds U+202E right-to-left override character to reverse rendering of file extensions or paths.'
  },
  {
    id: 'attack-zero-width-filter-evasion',
    input: 'https://camp\u200Bus.example/test',
    expectedVerdict: 'suspicious',
    category: 'Structural Attack',
    label: 'Zero-Width Space Filter Evasion',
    explanation: 'Embeds invisible zero-width space (U+200B) inside host string to bypass static keyword filters.'
  },

  // --- 3. REVIEW-CLASS LINKS (8 items) ---
  {
    id: 'review-shortener-bitly',
    input: 'https://bit.ly/3abcXYZ',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Bitly URL Redirection Service',
    explanation: 'Shortened URL obscures destination host; cannot be resolved safely offline without outbound network requests.'
  },
  {
    id: 'review-shortener-tinyurl',
    input: 'https://tinyurl.com/campus-event',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'TinyURL Redirection Service',
    explanation: 'Known URL shortener concealing target address behind opaque identifier.'
  },
  {
    id: 'review-rfc1918-class-c-private-ip',
    input: 'http://192.168.1.10/',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Private RFC 1918 Class C Subnet',
    explanation: 'Targets private intranet address unreachable from public internet; caution required for internal scanning.'
  },
  {
    id: 'review-rfc1918-class-a-private-ip',
    input: 'http://10.0.0.1/admin',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Private RFC 1918 Class A Subnet',
    explanation: 'Targets enterprise internal subnet gateway; requires local network context.'
  },
  {
    id: 'review-rfc1918-class-b-private-ip',
    input: 'http://172.16.0.5/gateway',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Private RFC 1918 Class B Subnet',
    explanation: 'Targets 172.16.0.0/12 private network range.'
  },
  {
    id: 'review-loopback-ip-host',
    input: 'http://127.0.0.1:8080/test',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Loopback Localhost Address (127.0.0.1)',
    explanation: 'Targets device local loopback interface rather than external network origin.'
  },
  {
    id: 'review-local-filesystem-scheme',
    input: 'file:///etc/passwd',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Local Filesystem Protocol (file://)',
    explanation: 'Directs device to inspect local filesystem storage rather than navigating remote web.'
  },
  {
    id: 'review-mail-client-protocol',
    input: 'mailto:security@campus.example',
    expectedVerdict: 'review',
    category: 'Review Class',
    label: 'Email Client Launch Handler (mailto:)',
    explanation: 'Triggers local default mail application draft rather than loading a web page.'
  },

  // --- 4. NON-URL PAYLOADS (6 items) ---
  {
    id: 'payload-upi-prefilled-amount',
    input: 'upi://pay?pa=campus-canteen@oksbi&pn=Campus%20Canteen&am=250&cu=INR',
    expectedVerdict: 'review',
    category: 'Non-URL Payload',
    label: 'UPI QR with Prefilled Amount & Untrusted Name',
    explanation: 'Deconstructs mobile payment intent. Flags pre-filled debit amount and marks claimed name as untrusted.'
  },
  {
    id: 'payload-upi-payee-only',
    input: 'upi://pay?pa=library-fines@sbi&pn=Campus%20Library',
    expectedVerdict: 'review',
    category: 'Non-URL Payload',
    label: 'UPI QR Payee-Only Intent',
    explanation: 'Dynamic amount payment request requiring user review of payee VPA in banking app.'
  },
  {
    id: 'payload-wifi-wpa2-config',
    input: 'WIFI:T:WPA;S:Campus_Guest_WiFi;P:Welcome2026;H:false;;',
    expectedVerdict: 'review',
    category: 'Non-URL Payload',
    label: 'Wi-Fi MECARD WPA Protected Network',
    explanation: 'MECARD configuration barcode for automated device Wi-Fi access point association.'
  },
  {
    id: 'payload-wifi-open-unencrypted',
    input: 'WIFI:S:University_Free_WiFi;T:nopass;;',
    expectedVerdict: 'review',
    category: 'Non-URL Payload',
    label: 'Wi-Fi MECARD Open / Unencrypted Network',
    explanation: 'Alerts that network specifies no encryption credentials; traffic exposed to local eavesdropping.'
  },
  {
    id: 'payload-plain-text-notice',
    input: 'Notice: Chemistry lab inventory check scheduled for 10 AM',
    expectedVerdict: 'safe',
    category: 'Non-URL Payload',
    label: 'Plain Informational Text QR',
    explanation: 'Contains non-executable descriptive text without URIs or system intent handlers.'
  },
  {
    id: 'payload-plain-text-room-badge',
    input: 'Room 304 Key Card Access - Authorized Faculty Only',
    expectedVerdict: 'safe',
    category: 'Non-URL Payload',
    label: 'Physical Access Badge Text QR',
    explanation: 'Descriptive facility text safely classified as non-executable content.'
  },

  // --- 5. DOCUMENTED KNOWN LIMITS (4 items) ---
  {
    id: 'limit-compromised-legitimate-domain',
    input: 'https://compromised-faculty-blog.com/login-form',
    expectedVerdict: 'safe',
    category: 'Known Limit',
    label: 'Compromised Legitimate Domain (Zero Syntactic Deception)',
    isKnownLimit: true,
    explanation: 'Link uses standard HTTPS and legitimate domain syntax without homoglyphs or traps. Offline structural analysis correctly clears URI syntax; detecting active compromised hosting requires live external domain reputation or threat intelligence feeds.'
  },
  {
    id: 'limit-newly-registered-ascii-domain',
    input: 'https://freshly-registered-phish-2026.net/portal',
    expectedVerdict: 'safe',
    category: 'Known Limit',
    label: 'Brand-New Malicious Domain with Standard Syntax',
    isKnownLimit: true,
    explanation: 'Link uses standard ASCII characters and valid HTTPS. Detecting newly registered malicious domains without structural anomalies requires external WHOIS age and reputation blocklist lookups.'
  },
  {
    id: 'limit-uncommon-generic-tld',
    input: 'https://lab-data.science/research-notes',
    expectedVerdict: 'safe',
    category: 'Known Limit',
    label: 'Benign Domain with Uncommon TLD (.science)',
    isKnownLimit: true,
    explanation: 'Uses uncommon generic TLD (.science) but adheres strictly to RFC formatting. Naive heuristic scoring often penalizes uncommon TLDs as spam; Link Sentinel verifies valid PSL registration offline, yielding to external domain reputation lookups for content trustworthiness.'
  },
  {
    id: 'limit-shared-cloud-serverless-worker',
    input: 'https://student-project-784.workers.dev/api',
    expectedVerdict: 'safe',
    category: 'Known Limit',
    label: 'Cloud Serverless Worker Subdomain (workers.dev)',
    isKnownLimit: true,
    explanation: 'Uses legitimate shared cloud infrastructure (workers.dev) without structural deceit. Differentiating malicious temporary worker endpoints from benign student projects requires live endpoint reputation and content inspection.'
  }
];

export default BENCHMARK_CORPUS;
