/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Cascadia Code", "Consolas", "monospace"],
      },
      colors: {
        brand: { 50: "#eef6ff", 100: "#d9eaff", 200: "#bcdaff", 400: "#5aa2ff", 500: "#2f7df6", 600: "#1d63db", 700: "#1a4fb0", 900: "#132c5c" },
        ink: { 950: "#0b1020", 900: "#111831", 800: "#1a2342", 700: "#26304f", 600: "#3a4568" },
      },
      boxShadow: { card: "0 1px 2px rgba(16,24,40,.05), 0 1px 3px rgba(16,24,40,.06)" },
    },
  },
  plugins: [],
};
