import { z } from "zod";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  authenticateUser,
  getSessionFromToken,
  invalidateSessionByToken,
} from "../services/authService.js";

const adminLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  deviceId: z.string().min(6),
  deviceLabel: z.string().optional(),
});

const extractBearerToken = (req) => {
  const header = req.headers.authorization ?? req.headers.Authorization;
  if (typeof header === "string" && header.toLowerCase().startsWith("bearer ")) {
    return header.slice(7).trim();
  }
  return undefined;
};

export const adminLoginHandler = asyncHandler(async (req, res) => {
  const payload = adminLoginSchema.parse(req.body);
  const result = await authenticateUser(
    payload.email,
    payload.password,
    payload.deviceId,
    payload.deviceLabel,
  );

  if (!result.user.isAdmin) {
    await invalidateSessionByToken(result.session.token, "Admin login denied: user is not an admin");
    res.status(403).json({ error: "NOT_ADMIN" });
    return;
  }

  res.status(200).json({
    ok: true,
    token: result.session.token,
    email: result.user.email,
    expiresAt: result.session.expiresAt,
  });
});

export const adminLogoutHandler = asyncHandler(async (req, res) => {
  const token = extractBearerToken(req) ?? req.body?.token;
  if (!token) {
    res.status(200).json({ ok: true });
    return;
  }

  await invalidateSessionByToken(token, "Admin logout");
  res.status(200).json({ ok: true });
});

export const adminSessionHandler = asyncHandler(async (req, res) => {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const result = await getSessionFromToken(token);
    if (!result || !result.user.isAdmin) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    res.status(200).json({
      ok: true,
      email: result.user.email,
      expiresAt: result.session.expiresAt,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "ACCOUNT_BLOCKED") {
      res.status(423).json({ error: "Account blocked" });
      return;
    }
    res.status(401).json({ error: "Invalid session" });
  }
});


