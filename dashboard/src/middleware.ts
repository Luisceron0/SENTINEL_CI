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

import { SESSION_COOKIE, getSessionToken } from "./lib/auth";

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
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://avatars.githubusercontent.com",
  );
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

  if (!isAuthenticated && context.url.pathname === "/logout") {
    response.headers.append(
      "Set-Cookie",
      `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`,
    );
  }

  return response;
});
