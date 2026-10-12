import { z } from "zod";
import {
  authenticateUser,
  completeDeviceVerification,
  getSessionFromToken,
  heartbeatSession,
  invalidateSessionByToken,
  seedDefaultUser,
} from "../services/authService.js";
import {
  sessionCookieName,
  sessionCookieOptions,
  expiredSessionCookieOptions,
} from "../utils/cookies.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { config } from "../config.js";

/**
 * The fingerprint block is optional on every field: a browser that blocks WebGL, or an older
 * browser missing an API, must still be able to sign in. Missing signals lower the confidence
 * score, and a low-confidence fingerprint is never used as evidence of sharing.
 */
const fingerprintSchema = z
  .object({
    userAgent: z.string().max(512).optional(),
    platform: z.string().max(128).optional(),
    cpuCores: z.number().optional(),
    deviceMemory: z.number().optional(),
    screenWidth: z.number().optional(),
    screenHeight: z.number().optional(),
    colorDepth: z.number().optional(),
    pixelRatio: z.number().optional(),
    maxTouchPoints: z.number().optional(),
    gpuVendor: z.string().max(256).optional(),
    gpuRenderer: z.string().max(512).optional(),
    canvasHash: z.string().max(128).optional(),
    audioHash: z.string().max(128).optional(),
    fontsHash: z.string().max(128).optional(),
    languages: z.union([z.string().max(256), z.array(z.string().max(64)).max(20)]).optional(),
    timezone: z.string().max(128).optional(),
  })
  .partial()
  .optional();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  deviceId: z.string().min(6),
  deviceLabel: z.string().max(512).optional(),
  fingerprint: fingerprintSchema,
});

const verifySchema = z.object({
  email: z.string().email(),
  challengeId: z.string().min(6),
  code: z.string().regex(/^\d{6}$/),
  deviceId: z.string().min(6),
  deviceLabel: z.string().max(512).optional(),
  fingerprint: fingerprintSchema,
});

const heartbeatSchema = z.object({
  deviceId: z.string().min(6).optional(),
  fingerprint: fingerprintSchema,
});

const bearerToken = (req) => {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice(7).trim();
  return req.cookies?.[sessionCookieName] ?? null;
};

export const loginHandler = asyncHandler(async (req, res) => {
  const payload = loginSchema.parse(req.body);

  const result = await authenticateUser({
    email: payload.email,
    password: payload.password,
    deviceId: payload.deviceId,
    deviceLabel: payload.deviceLabel,
    fingerprint: payload.fingerprint,
    ipAddress: req.ip,
    headers: req.headers,
  });

  // New or unverified device: hand back a challenge instead of a session.
  if (result.requiresDeviceVerification) {
    res.status(200).json({
      ok: false,
      requiresDeviceVerification: true,
      challengeId: result.challengeId,
      expiresAt: result.expiresAt,
      deviceLabel: result.deviceLabel,
      maskedEmail: result.maskedEmail,
      message:
        "This device is not yet authorised. We emailed a 6-digit code to the address on this account.",
    });
    return;
  }

  res.cookie(sessionCookieName, result.session.token, sessionCookieOptions);
  res.status(200).json({
    ok: true,
    reused: result.reused,
    rotated: result.rotated,
    token: result.session.token,
    heartbeatSeconds: config.device.heartbeatSeconds,
  });
});

export const verifyDeviceHandler = asyncHandler(async (req, res) => {
  const payload = verifySchema.parse(req.body);

  const result = await completeDeviceVerification({
    email: payload.email,
    challengeId: payload.challengeId,
    code: payload.code,
    deviceId: payload.deviceId,
    deviceLabel: payload.deviceLabel,
    fingerprint: payload.fingerprint,
    ipAddress: req.ip,
    headers: req.headers,
  });

  res.cookie(sessionCookieName, result.session.token, sessionCookieOptions);
  res.status(200).json({
    ok: true,
    token: result.session.token,
    replacedDevices: result.replacedDevices,
    heartbeatSeconds: config.device.heartbeatSeconds,
  });
});

/**
 * Called by the client on an interval. This is what keeps `lastSeenAt` fresh, and therefore what
 * makes "two devices were in use at the same time" a measurable fact rather than an assumption.
 */
export const heartbeatHandler = asyncHandler(async (req, res) => {
  const token = bearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Missing session" });
    return;
  }

  const payload = heartbeatSchema.parse(req.body ?? {});

  try {
    const result = await heartbeatSession({
      token,
      fingerprint: payload.fingerprint,
      deviceId: payload.deviceId,
      ipAddress: req.ip,
      headers: req.headers,
    });

    if (!result.ok) {
      res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
      if (result.error === "ACCOUNT_BLOCKED_SHARING") {
        res.status(423).json({
          error: "Account blocked",
          code: "ACCOUNT_BLOCKED_SHARING",
          caseId: result.caseId,
        });
        return;
      }
      res.status(401).json({ error: "Invalid session" });
      return;
    }

    res.status(200).json({ ok: true, heartbeatSeconds: result.heartbeatSeconds });
  } catch (error) {
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    if (error.message === "ACCOUNT_BLOCKED") {
      res.status(423).json({ error: "Account blocked", code: "ACCOUNT_BLOCKED" });
      return;
    }
    res.status(401).json({ error: "Invalid session" });
  }
});

export const logoutHandler = asyncHandler(async (req, res) => {
  const token = bearerToken(req);
  if (!token) {
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    res.status(200).json({ ok: true });
    return;
  }

  await invalidateSessionByToken(token, "User logged out");
  res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
  res.status(200).json({ ok: true });
});

export const sessionHandler = asyncHandler(async (req, res) => {
  const token = bearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Missing authorization header" });
    return;
  }

  try {
    const result = await getSessionFromToken(token);
    if (!result) {
      res.status(401).json({ error: "Invalid token" });
      return;
    }
    res.status(200).json({
      ok: true,
      email: result.user.email,
      deviceLabel: result.session.deviceLabel,
      heartbeatSeconds: config.device.heartbeatSeconds,
    });
  } catch (error) {
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    if (error instanceof Error && error.message === "ACCOUNT_BLOCKED") {
      res.status(423).json({ error: "Account blocked" });
      return;
    }
    res.status(401).json({ error: "Invalid session" });
  }
});

export const seedHandler = asyncHandler(async (_req, res) => {
  await seedDefaultUser();
  res.status(204).send();
});
