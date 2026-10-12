import { z } from "zod";
import { asyncHandler } from "../utils/asyncHandler.js";
import { sessionCookieName, expiredSessionCookieOptions } from "../utils/cookies.js";
import { getSessionFromToken } from "../services/authService.js";
import { recordSecurityEvent } from "../services/securityEventService.js";
import { recordInspectionReport } from "../services/inspectionService.js";
import { buildDeviceContext, matchDevice } from "../services/deviceService.js";
import { buildObservation } from "../services/evidenceService.js";
import { config } from "../config.js";

/**
 * Client security reports.
 *
 * This endpoint used to block an account permanently on a single unauthenticated-in-spirit POST:
 * the body said "DEVTOOLS_OPENED" and the server believed it. It now accepts a structured
 * report, records it as signed evidence, and leaves the decision to policy and to a human.
 */

const signalSchema = z.object({
  name: z.string().max(64),
  detail: z.string().max(500).optional(),
});

const fingerprintSchema = z.object({}).passthrough().optional();

const reportSchema = z.object({
  type: z.enum(["DEVTOOLS_OPENED", "CLIENT_INSPECTION"]),
  signals: z.array(signalSchema).max(20).optional(),
  message: z.string().max(500).optional(),
  page: z.string().max(200).optional(),

  /**
   * Raw measurements behind the report. Stored verbatim so a disputed case can be re-examined:
   * if a user says "I only zoomed in", the recorded zoom level either supports that or does not.
   */
  diagnostics: z
    .object({
      outerWidth: z.number().optional(),
      innerWidth: z.number().optional(),
      outerHeight: z.number().optional(),
      innerHeight: z.number().optional(),
      widthDelta: z.number().optional(),
      heightDelta: z.number().optional(),
      devicePixelRatio: z.number().optional(),
      zoomLevel: z.number().optional(),
      screenWidth: z.number().optional(),
      screenHeight: z.number().optional(),
      visibility: z.string().max(32).optional(),
      consoleTimingMs: z.number().optional(),
      orientation: z.string().max(32).optional(),
    })
    .passthrough()
    .optional(),

  deviceId: z.string().max(200).optional(),
  fingerprint: fingerprintSchema,
  token: z.string().max(512).optional(),
});

const bearerToken = (req) => {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice(7).trim();
  return req.cookies?.[sessionCookieName] ?? null;
};

export const securityEventHandler = asyncHandler(async (req, res) => {
  const payload = reportSchema.parse(req.body);
  const token = bearerToken(req) ?? payload.token ?? null;

  // An anonymous report cannot be attributed, so it is logged and nothing more.
  if (!token) {
    await recordSecurityEvent({
      type: "DEVTOOLS_REPORTED",
      deviceId: payload.deviceId,
      message: payload.message ?? "Client inspection report without a session",
      metadata: { signals: payload.signals?.map((s) => s.name), anonymous: true },
    });
    res.status(202).json({ ok: true, recorded: true, action: "none" });
    return;
  }

  let result;
  try {
    result = await getSessionFromToken(token);
  } catch (error) {
    // Already-blocked account: clear the cookie and say so, but do not re-penalise.
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    res.status(200).json({ ok: true, recorded: false });
    return;
  }

  if (!result) {
    res.status(200).json({ ok: true, recorded: false });
    return;
  }

  const { session, user } = result;

  const context = await buildDeviceContext({
    fingerprint: payload.fingerprint,
    clientDeviceId: payload.deviceId ?? session.deviceId,
    ip: req.ip,
    headers: req.headers,
  });
  context.observation = buildObservation(context);

  const match = await matchDevice(user, context);
  context.deviceKey = match.device?.deviceKey ?? session.deviceKey ?? null;

  const outcome = await recordInspectionReport({
    user,
    session,
    report: {
      signals: payload.signals ?? [],
      message: payload.message,
      page: payload.page,
      diagnostics: payload.diagnostics,
    },
    context,
  });

  if (outcome.blocked) {
    res.cookie(sessionCookieName, "", expiredSessionCookieOptions);
    res.status(423).json({
      blocked: true,
      code: "ACCOUNT_BLOCKED_INSPECTION",
      caseId: outcome.caseId,
    });
    return;
  }

  /**
   * The normal path. 202 with action "none" tells the client its report was filed and that it
   * must not log the user out - the client no longer decides the penalty.
   */
  res.status(202).json({
    ok: true,
    recorded: true,
    action: "none",
    caseId: outcome.caseId,
    policy: config.inspection.policy,
  });
});
