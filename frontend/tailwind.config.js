/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          950: '#060913',
          900: '#0b1120',
          850: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
          500: '#64748b',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          violet: '#8b5cf6',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#38bdf8',
          info: '#94a3b8',
          success: '#10b981'
        }
      }
    },
  },
  plugins: [],
}
