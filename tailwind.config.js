/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './*.html',
    './tools/**/*.html',
    './tools/**/*.js',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0f1117',
          card:    '#1a1d27',
          border:  '#2a2d3a',
          hover:   '#22253a',
        },
        accent: {
          DEFAULT: '#6366f1',
          hover:   '#4f46e5',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}

