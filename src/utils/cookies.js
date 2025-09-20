import { config } from "../config.js";

const maxAgeMs = () => config.sessionTtlMinutes * 60 * 1000;

export const sessionCookieName = "session_token";

export const sessionCookieOptions = {
  httpOnly: true,
  sameSite: "strict",
  secure: config.nodeEnv === "production",
  path: "/",
  maxAge: maxAgeMs(),
};

export const expiredSessionCookieOptions = {
  ...sessionCookieOptions,
  maxAge: 0,
};