/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "background": "#070d18",
        "surface": "#0c1729",
        "surface-container": "#111f36",
        "surface-container-high": "#182844",
        "surface-container-highest": "#213454",
        "surface-container-low": "#0b1424",
        "surface-container-lowest": "#060b14",
        "primary": "#c3f5ff",
        "primary-container": "#00e5ff",
        "on-primary-container": "#003b44",
        "on-surface": "#e2e8f0",
        "on-surface-variant": "#94a3b8",
        "outline": "#475569",
        "outline-variant": "#1e293b",
        "tertiary": "#34d399",
        "error": "#f87171",
        "error-container": "#450a0a"
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', 'monospace']
      }
    },
  },
  plugins: [],
};
