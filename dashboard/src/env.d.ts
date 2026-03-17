/*
File Purpose:
- Provide ambient type declarations for Astro dashboard modules and environment variables.

Key Security Considerations:
- Keeps type contracts explicit and avoids unsafe implicit-any drift in UI code.

OWASP 2025 Categories Addressed:
- A05, A10
*/

/// <reference types="astro/client" />

interface ImportMetaEnv {
  readonly SENTINEL_API_ENDPOINT?: string;
  readonly PUBLIC_SENTINEL_API_ENDPOINT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare module "astro:middleware" {
  export function defineMiddleware(handler: any): any;
}

declare module "react";
declare module "react/jsx-runtime";
declare module "recharts";

declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
}
