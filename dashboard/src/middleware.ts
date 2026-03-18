/*
File Purpose:
- Enforce dashboard security headers and session gate in Astro middleware.

Key Security Considerations:
- Adds CSP and anti-clickjacking headers on every response.
- Redirects unauthenticated users away from protected pages.

OWASP 2025 Categories Addressed:
- A01, A02, A07, A08
*/

import { defineMiddleware } from "astro:middleware";

import { clearSessionCookie, getSessionToken } from "./lib/auth";

const PUBLIC_PATH_PREFIXES = ["/login", "/auth/callback", "/favicon", "/_astro"];

type MiddlewareContext = {
  request: Request;
  url: URL;
  redirect: (path: string, status?: number) => Response;
};

type MiddlewareNext = () => Promise<Response>;

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATH_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

export const onRequest = defineMiddleware(async (context: MiddlewareContext, next: MiddlewareNext) => {
  if (context.url.pathname === "/logout") {
    const secure = context.url.protocol === "https:";
    const response = context.redirect("/login", 302);
    response.headers.append("Set-Cookie", clearSessionCookie({ secure }));
    return response;
  }

  const token = getSessionToken(context.request.headers.get("cookie"));
  const isAuthenticated = Boolean(token);

  if (!isAuthenticated && !isPublicPath(context.url.pathname)) {
    return context.redirect("/login", 302);
  }

  if (isAuthenticated && context.url.pathname === "/login") {
    return context.redirect("/", 302);
  }

  const response = await next();
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://avatars.githubusercontent.com; font-src 'self' data:; connect-src 'self' https://*.supabase.co",
  );
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

  return response;
});
