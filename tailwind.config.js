/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
  ],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        cyber: {
          primary: '#00ff9f',
          secondary: '#00b8ff',
          accent: '#d600ff',
          text: '#e0e0e0',
          muted: '#858585',
          border: 'rgba(0, 255, 159, 0.3)',
          hover: 'rgba(0, 255, 159, 0.1)',
          background: '#050505',
          card: 'rgba(17, 17, 17, 0.7)',
          glass: 'rgba(255, 255, 255, 0.05)',
        },
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        cyber: ['Orbitron', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        'pulse-border': {
          '0%, 100%': { borderColor: 'rgba(0, 255, 159, 0.5)', boxShadow: '0 0 5px rgba(0, 255, 159, 0.2)' },
          '50%': { borderColor: 'rgba(0, 255, 159, 1)', boxShadow: '0 0 15px rgba(0, 255, 159, 0.5)' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        'glow': {
          'from': { textShadow: '0 0 5px #00ff9f, 0 0 10px #00ff9f' },
          'to': { textShadow: '0 0 10px #00ff9f, 0 0 20px #00ff9f, 0 0 30px #00ff9f' },
        },
        'scanline': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'glitch': {
          '0%': { textShadow: '-2px 0 #00ff9f, 2px 0 #00b8ff, -4px -4px #d600ff' },
          '14%': { textShadow: '-2px 0 #00ff9f, 2px 0 #00b8ff, -4px -4px #d600ff' },
          '15%': { textShadow: '-2px -2px #00ff9f, 2px 2px #00b8ff, -4px 0px #d600ff' },
          '49%': { textShadow: '-2px -2px #00ff9f, 2px 2px #00b8ff, -4px 0px #d600ff' },
          '50%': { textShadow: '2px 2px #00ff9f, -2px -2px #00b8ff, 0px -4px #d600ff' },
          '99%': { textShadow: '2px 2px #00ff9f, -2px -2px #00b8ff, 0px -4px #d600ff' },
          '100%': { textShadow: '-2px 0 #00ff9f, 2px 0 #00b8ff, -4px -4px #d600ff' },
        },
        'neon-pulse': {
          '0%, 100%': { 
            textShadow: '0 0 10px #00ff9f, 0 0 20px #00ff9f, 0 0 30px #00ff9f',
            boxShadow: '0 0 10px #00ff9f, 0 0 20px #00ff9f, 0 0 30px #00ff9f',
          },
          '50%': { 
            textShadow: '0 0 20px #00ff9f, 0 0 40px #00ff9f, 0 0 60px #00ff9f',
            boxShadow: '0 0 20px #00ff9f, 0 0 40px #00ff9f, 0 0 60px #00ff9f',
          },
        },
        'circuit-spark': {
          '0%, 100%': {
            boxShadow: '0 0 5px #00ff9f, inset 0 0 5px rgba(0, 255, 159, 0.3)',
          },
          '50%': {
            boxShadow: '0 0 20px #00ff9f, 0 0 30px #00b8ff, inset 0 0 10px rgba(0, 255, 159, 0.5)',
          },
        },
        'electric-glow': {
          '0%, 100%': {
            boxShadow: '0 0 10px rgba(0, 255, 159, 0.4), 0 0 20px rgba(0, 184, 255, 0.2)',
          },
          '50%': {
            boxShadow: '0 0 20px rgba(0, 255, 159, 0.8), 0 0 40px rgba(0, 184, 255, 0.4), 0 0 60px rgba(214, 0, 255, 0.2)',
          },
        },
        'slide-in-left': {
          'from': { transform: 'translateX(-100%)' },
          'to': { transform: 'translateX(0)' },
        },
        'particle-float': {
          '0%, 100%': { transform: 'translate(0, 0) scale(1)', opacity: '0' },
          '10%': { opacity: '0.5' },
          '90%': { opacity: '0.5' },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        'pulse-border': 'pulse-border 2s infinite',
        'float': 'float 6s ease-in-out infinite',
        'float-fast': 'float 3s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scanline': 'scanline 8s linear infinite',
        'glitch': 'glitch 2s infinite',
        'neon-pulse': 'neon-pulse 1.5s ease-in-out infinite',
        'circuit-spark': 'circuit-spark 1s ease-in-out infinite',
        'electric-glow': 'electric-glow 2s ease-in-out infinite',
        'slide-in-left': 'slide-in-left 0.3s ease-out',
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(to right, #00ff9f, #00b8ff)',
        'glass-gradient': 'linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05))',
      },
      boxShadow: {
        'neon': '0 0 5px theme("colors.cyber.primary"), 0 0 20px theme("colors.cyber.primary")',
        'neon-strong': '0 0 10px theme("colors.cyber.primary"), 0 0 40px theme("colors.cyber.primary")',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
}
