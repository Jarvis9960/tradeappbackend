import { config } from "../config.js";

const maxAgeMs = () => config.sessionTtlMinutes * 60 * 1000;

export const sessionCookieName = "session_token";

export const sessionCookieOptions = {
  httpOnly: true,
  sameSite: config.nodeEnv === "production" ? "none" : "lax",
  secure: config.nodeEnv === "production",
  path: "/",
  domain: config.nodeEnv === "production" ? config.cookieDomain : undefined,
  maxAge: maxAgeMs(),
};

export const expiredSessionCookieOptions = {
  ...sessionCookieOptions,
  maxAge: 0,
};