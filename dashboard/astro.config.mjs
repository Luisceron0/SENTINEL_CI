/*
File Purpose:
- Configure Astro dashboard with React islands, Tailwind integration, and Vercel adapter.

Key Security Considerations:
- Uses server output mode to support authenticated SSR pages.
- Keeps adapter/runtime explicit for deployment predictability.

OWASP 2025 Categories Addressed:
- A02, A06, A10
*/

import { defineConfig } from "astro/config";
import react from "@astrojs/react";
import tailwind from "@astrojs/tailwind";
import vercel from "@astrojs/vercel/serverless";

export default defineConfig({
  output: "server",
  adapter: vercel(),
  integrations: [react(), tailwind()],
  vite: {
    build: {
      target: "es2022",
    },
  },
});
