// File Purpose:
// - Define flat ESLint config (v9+) for dashboard TypeScript/TSX/Astro sources.
//
// Key Security Considerations:
// - Keep unsafe JS patterns blocked and avoid permissive typing in UI code.
//
// OWASP 2025 Categories Addressed:
// - A03, A05, A10

import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import astroParser from "astro-eslint-parser";
import astroPlugin from "eslint-plugin-astro";

const secureRules = {
  "no-console": ["error", { allow: ["warn", "error"] }],
  "no-eval": "error",
  "no-implied-eval": "error",
  "@typescript-eslint/no-explicit-any": "error",
};

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/**", "**/.astro/**"],
  },
  {
    files: ["dashboard/src/**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: secureRules,
  },
  {
    files: ["dashboard/src/**/*.astro"],
    languageOptions: {
      parser: astroParser,
      parserOptions: {
        parser: tsParser,
        extraFileExtensions: [".astro"],
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    plugins: {
      astro: astroPlugin,
      "@typescript-eslint": tsPlugin,
    },
    rules: secureRules,
  },
];
