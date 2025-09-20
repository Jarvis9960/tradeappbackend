import { z } from "zod";
import {
  authenticateUser,
  getSessionFromToken,
  invalidateSessionByToken,
  seedDefaultUser,
} from "../services/authService.js";
import { sessionCookieName, sessionCookieOptions, expiredSessionCookieOptions } from "../utils/cookies.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  deviceId: z.string().min(6),
  deviceLabel: z.string().optional(),
});

export const loginHandler = asyncHandler(async (req, res) => {
  const payload = loginSchema.parse(req.body);

  const result = await authenticateUser(payload.email, payload.password, payload.deviceId, payload.deviceLabel);
  res.status(200).json({ 
    ok: true, 
    reused: result.reused,
    token: result.session.token 
  });
});

export const logoutHandler = asyncHandler(async (req, res) => {
  const token = req.cookies?.[sessionCookieName];
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
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: "Missing authorization header" });
    return;
  }

  const token = authHeader.split(' ')[1];
  try {
    const result = await getSessionFromToken(token);
    if (!result) {
      res.status(401).json({ error: "Invalid token" });
      return;
    }
    res.status(200).json({ ok: true, email: result.user.email });
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