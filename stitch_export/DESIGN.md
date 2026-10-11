---
name: Link Sentinel Design System
colors:
  surface: '#0c1322'
  surface-dim: '#0c1322'
  surface-bright: '#32394a'
  surface-container-lowest: '#070e1d'
  surface-container-low: '#151b2b'
  surface-container: '#191f2f'
  surface-container-high: '#232a3a'
  surface-container-highest: '#2e3545'
  on-surface: '#dce2f8'
  on-surface-variant: '#bac9cc'
  inverse-surface: '#dce2f8'
  inverse-on-surface: '#2a3041'
  outline: '#849396'
  outline-variant: '#3b494c'
  surface-tint: '#00daf3'
  primary: '#c3f5ff'
  on-primary: '#00363d'
  primary-container: '#00e5ff'
  on-primary-container: '#00626e'
  inverse-primary: '#006875'
  secondary: '#ddb7ff'
  on-secondary: '#490080'
  secondary-container: '#6f00be'
  on-secondary-container: '#d6a9ff'
  tertiary: '#a8ffd2'
  on-tertiary: '#003824'
  tertiary-container: '#5be9ad'
  on-tertiary-container: '#006645'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#9cf0ff'
  primary-fixed-dim: '#00daf3'
  on-primary-fixed: '#001f24'
  on-primary-fixed-variant: '#004f58'
  secondary-fixed: '#f0dbff'
  secondary-fixed-dim: '#ddb7ff'
  on-secondary-fixed: '#2c0051'
  on-secondary-fixed-variant: '#6900b3'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0c1322'
  on-background: '#dce2f8'
  surface-variant: '#2e3545'
typography:
  headline-xl:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 36px
    fontWeight: '800'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 28px
    fontWeight: '800'
    lineHeight: 34px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
    letterSpacing: 0.01em
  headline-md:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 20px
    fontWeight: '700'
    lineHeight: 28px
    letterSpacing: 0.02em
  headline-sm:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 16px
    fontWeight: '700'
    lineHeight: 24px
    letterSpacing: 0.04em
  body-lg:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-code-lg:
    fontFamily: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation
      Mono', monospace
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 22px
    letterSpacing: -0.01em
  label-code-md:
    fontFamily: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation
      Mono', monospace
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: 0em
  label-code-sm:
    fontFamily: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation
      Mono', monospace
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.02em
  label-caps:
    fontFamily: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
      sans-serif
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.08em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-md: 1.5rem
  gutter-lg: 2rem
  margin: 1rem
  margin-md: 1.5rem
  margin-lg: 2.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
  space-2xl: 3rem
---

## Brand & Style

This design system powers a privacy-first, explainable link and QR code security inspector engineered specifically for collegiate environments (students, faculty, and administrative staff). It blends institutional credibility with modern tactical cybersecurity telemetry.

### Aesthetic Persona
- **High-Trust Technical Precision:** Evokes rigorous network defense tools without resorting to panic-inducing tropes or obscure security jargon.
- **Explainable & Educational:** Demystifies adversarial mechanics (typosquatting, lookalike unicode, open redirects, decoy subdomains) using plain-English diagnostics and structured anatomy breakdowns.
- **Zero-Trust Visuals:** Deep abyssal navy-to-blue backdrops with localized luminescent borders, crisp geometric surfaces, and focused telemetry glows.

### Design Movements
- **Dark Tactical Glassmorphism & High-Contrast Utility:** Layered translucent deep slate/teal panels (`#0D1D2B`, `#0E2433`) suspended over deep dark navy gradients, bound by precision hairline borders with verdict-driven edge glows.
- **Data-Dense Monospace Tokenization:** URL breakdowns prioritize syntactic clarity via structured chip ribbons, visual path segmentation, and explicit status hierarchy.

## Colors

The palette operates strictly in dark mode, balancing deep navy ground tones with phosphorescent signal accents for immediate verdict triage.

### Surface System
- **Base Canvas:** Linear gradient from `#060B19` (zenith) to `#0B172E` (nadir).
- **Surface Level 1 (Container Base):** `#0A1120` — Low-contrast structural underlays and drawer wells.
- **Surface Level 2 (Default Card/Panel):** `#0D1D2B` with 80% opacity and 12px backdrop blur.
- **Surface Level 3 (Elevated / Nested):** `#0E2433` to `#13273C` — Interactive segments, input fields, and hover states.

### Core Signal Tokens
- **Primary Accent (`#00E5FF`):** Scan radar sweeps, interactive link focus states, scanner trigger buttons, and structural active rings.
- **Secondary Accent (`#A855F7`):** Academic context alerts, meta-heuristics, entropy analysis ratings, and technical explainability tags.

### Semantic Triage Accents
- **Verdict Safe (`#10B981` / Dark Variant `#059669`):** Verified academic domains, genuine institutional host chips, validated HTTPS handshake statuses.
- **Verdict Review Needed (`#F59E0B` / Dark Variant `#D97706`):** Shortened links, multi-hop redirects, newly registered top-level domains, non-standard port allocations.
- **Verdict Suspicious / Threat (`#EF4444` / Dark Variant `#DC2626`):** Lookalike glyphs, phishing signatures, deceptive subdomains, credential harvest forms.

### Border & Luminance Rules
- Boundaries rely on hairline 1px strokes with calibrated alpha:
  - Standard container: `rgba(0, 229, 255, 0.12)`
  - Safe card state: `rgba(16, 185, 129, 0.35)` with `0 0 12px rgba(16, 185, 129, 0.15)`
  - Review card state: `rgba(245, 158, 11, 0.40)` with `0 0 14px rgba(245, 158, 11, 0.18)`
  - Threat card state: `rgba(239, 68, 68, 0.45)` with `0 0 16px rgba(239, 68, 68, 0.22)`

## Typography

Strict reliance on native platform stacks guarantees zero remote network payloads, offline operational security, and instant render latency.

### Stack Declarations
- **UI & Editorial Stack:** `system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Telemetry & URL Anatomy Stack:** `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace`

### Typography Rules
- **Uppercase Structural Labels:** Section titles, risk badges, and scanner metadata use `label-caps` (`text-transform: uppercase`) paired with wide tracking (`letter-spacing: 0.08em`) to establish crisp hierarchy.
- **URL Dissection Alignment:** URL protocols, root hosts, path segments, and query parameters render exclusively via `label-code-md` or `label-code-lg`. No proportional fonts may be applied to raw web addresses.
- **Rule Card Explanations:** Explanations of risk indicators adopt `body-md` in high-readability off-white (`#E2E8F0`), maintaining contrast ratios above 7:1 against container surfaces.

## Layout & Spacing

The layout model employs a max-width single/dual column tactical dashboard architecture. It prioritizes fluid adaptation for mobile QR scanning while expanding into multi-panel triage workspaces on desktop screens.

### Grid & Breakpoints
- **Mobile (< 640px):** Single vertical stream. 4-column fluid layout with `margin: 1rem` and `gutter: 1rem`. Component density adjusts to enforce full-width thumb accessibility.
- **Tablet (640px - 1024px):** Single centered column (max-width `720px`) with `margin: 1.5rem`.
- **Desktop (> 1024px):** Centered operational canvas (max-width `1140px`) using an 8/4 asymmetrical split:
  - **Primary Column (8 cols):** Target URL input, real-time anatomy visualizer, and risk rules breakdown.
  - **Telemetry Rail (4 cols):** Verdict shield, campus trust badge, heuristic confidence scores, and raw payload metadata.

### Touch Target Integrity
- Every interactive element (URL chip, dismiss trigger, expand button, scan initiate) maintains an absolute minimum clickable dimension of `44px × 44px`.

## Elevation & Depth

Visual hierarchy does not use diffuse realistic dropshadows. It relies on chromatic back-glows and stepped structural luminance tiers to distinguish foreground interactions from static telemetry.

### Elevation Hierarchy
- **Level 0 (App Shell):** Gradient base (`#060B19` to `#0B172E`). No elevation.
- **Level 1 (Structural Panels & Rule Cards):** Solid `#0D1D2B` at 85% opacity, backdrop filter `blur(12px)`, border 1px solid `rgba(0, 229, 255, 0.12)`.
- **Level 2 (Active Inspection Elements & Input Surfaces):** `#0E2433` solid, border 1px solid `rgba(0, 229, 255, 0.28)`, shadow `0 4px 20px rgba(0, 0, 0, 0.45)`.
- **Level 3 (Modal Sheets & QR Camera Viewport Frame):** `#13273C`, border 1px solid `rgba(0, 229, 255, 0.45)`, shadow `0 12px 36px rgba(0, 0, 0, 0.65)`.

### Chromatic Glows
Dynamic states project focused edge illumination:
- **Scan Safe Focus:** `box-shadow: 0 0 0 1px #10B981, 0 0 24px rgba(16, 185, 129, 0.20)`
- **Review Warning Focus:** `box-shadow: 0 0 0 1px #F59E0B, 0 0 24px rgba(245, 158, 11, 0.22)`
- **Suspicious Threat Focus:** `box-shadow: 0 0 0 1px #EF4444, 0 0 32px rgba(239, 68, 68, 0.28)`

## Shapes

The design system applies a disciplined rounded geometry (`roundedness: 2`), balancing industrial tooling with tactile mobile ergonomics.

### Corner Radii Guidelines
- **Micro-tokens & Chips (`rounded` / 0.375rem - 0.5rem):** Individual URL tokens (subdomain, host, port, path parameter chips) and status pills.
- **Form Controls & Inputs (`rounded-lg` / 0.75rem - 1rem):** Primary input bars, scanner activation triggers, and action buttons.
- **Containers & Verdict Cards (`rounded-xl` / 1rem - 1.5rem):** Main scan results card, threat explanation panels, and QR viewfinder modules.
- **Camera Frame Reticle (`rounded-2xl` / 1.5rem):** QR target alignment masks.

## Components

All icons are rendered strictly as self-contained inline vector outlines (24x24 viewBox, 2px stroke, non-scaling stroke, zero external font or network image dependencies).

### 1. Interactive URL Anatomy Tokenizer
- **Structure:** Horizontal flexbox container with auto-wrapping (`gap: 6px`) wrapping segmented tokens:
  - `Scheme`: Subdued gray-blue outline badge (`http://` highlighted as warning amber, `https://` neutral muted).
  - `Decoy Subdomains`: Outlined in high-alert red with subtle striped background pattern to signify deception.
  - `Real Host (Registered Domain)`: Highlighted with an emerald green glow (`#10B981`), solid dark green base (`rgba(16, 185, 129, 0.12)`), and a green shield SVG icon.
  - `Top-Level Domain (TLD)`: Outlined chip displaying reputation category (e.g., `.edu` flagged as Academic Institutional).
  - `Path & Query Params`: Monospaced muted slate chips with click-to-decode features for obfuscated hexadecimal or base64 parameters.
- **Interaction:** Tapping any segment surfaces a contextual micro-popover explaining its specific role in link routing.

### 2. Explainable Plain-English Rule Cards
- **Structure:** Modular card (`#0D1D2B`) with a 1px colored left accent border (3px solid matching severity level).
- **Header:** Displays an inline status SVG icon, plain-language title (e.g., *"Hidden Destination Detected"*), and risk category tag.
- **Content:** Two-tier explanation:
  - *What we found:* "The link appears to point to university-portal.edu, but actually resolves to external-tracker.ru."
  - *Why it matters:* "Attackers frequently mimic campus login systems to harvest university credentials."
- **Expandable Diagnostic:** Monospace toggle revealing DNS routing records, redirect hops, and SSL issuer information.

### 3. Verdict Hero Banner
- **Safe Verdict:** Deep emerald wash gradient (`linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(13, 29, 43, 0.95))`), featuring a checkmark-shield vector icon and primary action: *"Open in University Sandbox"*.
- **Review Needed Verdict:** Amber-gold ambient halo, warning triangle icon, and primary action: *"Proceed with Previews Disabled"*.
- **Suspicious Verdict:** Pulsing crimson aura (`#EF4444`), octagonal alert vector icon, explicit headline: *"Malicious Impersonation Identified"*, and prominent action: *"Block & Report to Campus IT"*.

### 4. Input Fields & Scanner Triggers
- **Link Inspector Bar:** Single unified text bar with a dark teal ground (`#0E2433`), prominent 48px height, internal paste button, QR launch trigger button, and auto-sanitization indicator.
- **Focus States:** High-visibility Cyan (`#00E5FF`) outer halo (`ring-2 ring-cyan-400/40`).

### 5. Buttons & Controls
- **Primary Action (Scan / Confirm):** High-contrast cyan background (`#00E5FF`), deep navy label (`#060B19`, bold 700), minimum height `44px`, corner radius `0.75rem`.
- **Destructive Action (Block / Quarantine):** Crimson fill (`#DC2626`), white text, red glowing border.
- **Secondary Ghost Action:** Transparent surface, 1px border `rgba(0, 229, 255, 0.25)`, cyan text, hover background `rgba(0, 229, 255, 0.08)`.
- **Toggle / Radio Toggles:** Flat slate capsules with segmented thumb indicators highlighting active inspection modes: Link Text, QR Stream, or Deep Redirect Walk.