/*
File Purpose:
- Provide dashboard auth/session helpers for GitHub OAuth via Supabase and secure cookie handling.

Key Security Considerations:
- Uses HttpOnly/Secure/SameSite=Strict cookie defaults and explicit max-age control.
- Avoids exposing access tokens in URL/query after callback processing.

OWASP 2025 Categories Addressed:
- A02, A07, A08, A10
*/

export const SESSION_COOKIE = "sentinel_session";
export const SESSION_MAX_AGE_SECONDS = 86400;

export type SessionCookieOptions = {
  secure: boolean;
};

export function getSessionToken(cookieHeader: string | null): string | null {
  if (!cookieHeader) {
    return null;
  }

  const parts = cookieHeader.split(";").map((item) => item.trim());
  for (const part of parts) {
    if (part.startsWith(`${SESSION_COOKIE}=`)) {
      const value = part.slice(SESSION_COOKIE.length + 1);
      return decodeURIComponent(value);
    }
  }
  return null;
}

export function buildSessionSetCookie(token: string, options: SessionCookieOptions): string {
  const attributes = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
  ];

  if (options.secure) {
    attributes.push("Secure");
  }

  return attributes.join("; ");
}

export function clearSessionCookie(options: SessionCookieOptions): string {
  return buildSessionSetCookie("", options).replace(`Max-Age=${SESSION_MAX_AGE_SECONDS}`, "Max-Age=0");
}

export function buildGithubOAuthStartUrl(origin: string): string {
  const redirectTo = encodeURIComponent(`${origin}/auth/callback`);
  return `${origin}/api/auth/github/start?redirect_to=${redirectTo}`;
}
