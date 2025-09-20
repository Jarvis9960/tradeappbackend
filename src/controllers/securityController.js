import { z } from "zod";
import { asyncHandler } from "../utils/asyncHandler.js";
import { sessionCookieName, expiredSessionCookieOptions } from "../utils/cookies.js";
import { getSessionFromToken, blockUserForDevtools } from "../services/authService.js";
import { recordSecurityEvent } from "../services/securityEventService.js";

const securitySchema = z.object({
  type: z.literal("DEVTOOLS_OPENED"),
  deviceId: z.string().optional(),
  message: z.string().optional(),
});

export const securityEventHandler = asyncHandler(async (req, res) => {
  const payload = securitySchema.parse(req.body);
  const token = req.cookies?.[sessionCookieName];
  const message = payload.message ?? "Developer tools detected on client";

  if (!token) {
    await recordSecurityEvent({
      type: payload.type,
      deviceId: payload.deviceId,
      message,
      email: undefined,
    });
    res.status(200).json({ ok: true });
    return;
  }

  try {
    const session = await getSessionFromToken(token);
    if (!session) {
      res.status(200).json({ ok: true });
      return;
    }
    await blockUserForDevtools(session.user, payload.deviceId ?? undefined, message);
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    res.status(423).json({ blocked: true });
  } catch (error) {
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    res.status(200).json({ ok: true });
  }
});