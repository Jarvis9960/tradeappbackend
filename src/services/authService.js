import bcrypt from "bcryptjs";
import { findUserByEmail, addAuditEvent, createUser, markUserBlocked } from "./userService.js";
import {
  issueSession,
  findSessionByToken,
  revokeSession,
  revokeAllSessionsForUser,
  touchSession,
} from "./sessionService.js";
import { recordSecurityEvent } from "./securityEventService.js";
import { buildDeviceContext, evaluateLogin, recordObservation, matchDevice } from "./deviceService.js";
import {
  issueDeviceChallenge,
  verifyDeviceChallenge,
  demoteOtherDevices,
} from "./deviceVerificationService.js";
import { appendEvidence, buildSharingReport, renderProofNarrative } from "./evidenceService.js";
import { sendAccountBlockedEmail, sendDeviceSwitchNotice } from "./emailService.js";
import { DeviceModel } from "../models/Device.js";
import { config } from "../config.js";

const ensureUserExists = async (email, password, options = {}) => {
  const existing = await findUserByEmail(email);
  if (existing) {
    if (options.isAdmin && !existing.isAdmin) {
      existing.isAdmin = true;
      await existing.save();
    }
    return existing;
  }
  const passwordHash = await bcrypt.hash(password, 10);
  return createUser({ email, passwordHash, ...options });
};

/**
 * Block an account for provable concurrent use, and record the proof.
 *
 * The evidence record is written *before* the block takes effect, carrying both devices'
 * fingerprints, both networks, the overlap window and the individual scoring factors. That
 * record is what support shows a user who says they never used a second device.
 */
const blockForConcurrentUse = async (user, context, concurrency) => {
  const incoming = context.observation;
  const other = concurrency.otherDevice;
  const otherIp = (other.observedIps ?? []).slice(-1)[0] ?? {};

  const evidence = await appendEvidence({
    user,
    kind: "CONCURRENT_USE_BLOCKED",
    deviceKey: other.deviceKey,
    payload: {
      observation: incoming,
      sharingScore: concurrency.score,
      threshold: config.device.blockScore,
      factors: concurrency.factors,
      comparison: concurrency.comparison,
      travel: concurrency.travel,
      overlap: concurrency.overlap,
      existingDevice: {
        deviceKey: other.deviceKey,
        deviceDescription: other.label,
        platform: other.platform,
        signals: other.signals,
        lastSeenAt: other.lastSeenAt,
        loginCount: other.loginCount,
        verifiedAt: other.verifiedAt,
        ip: otherIp.ip ?? null,
        isp: otherIp.isp ?? null,
        city: otherIp.city ?? null,
        country: otherIp.country ?? null,
      },
      incomingDevice: {
        deviceDescription: incoming.deviceDescription,
        signals: incoming.signals,
        observedAt: incoming.observedAt,
        ip: incoming.network.ip,
        isp: incoming.network.isp,
        city: incoming.network.city,
        country: incoming.network.country,
      },
    },
    narrative:
      `Two different devices were in use on this account at the same time. ` +
      `${other.label} held a live session ${concurrency.overlap.minutesApart} minutes before ` +
      `${incoming.deviceDescription} attempted access. Fingerprint similarity between them was ` +
      `${Math.round((concurrency.comparison?.similarity ?? 0) * 100)}%, below the ` +
      `${Math.round(config.device.matchThreshold * 100)}% threshold that the same device scores ` +
      `after clearing its browser data.`,
  });

  const reason = `Concurrent use of two devices detected (case ${evidence.recordHash.slice(0, 12)})`;
  const blockedUser = await markUserBlocked(user, reason);
  await revokeAllSessionsForUser(blockedUser, reason);

  await recordSecurityEvent({
    type: "CONCURRENT_DEVICE_BLOCKED",
    email: user.email,
    deviceId: context.clientDeviceId,
    deviceKey: other.deviceKey,
    message: reason,
    user: blockedUser,
    metadata: {
      caseId: evidence.recordHash.slice(0, 12),
      evidenceSeq: evidence.seq,
      sharingScore: concurrency.score,
      factors: concurrency.factors,
      ipAddress: incoming.network.ip,
      userAgent: incoming.requestHeaders.userAgent,
    },
  });

  // Give the user the reasoning immediately, so a dispute starts from the facts.
  try {
    const report = await buildSharingReport(blockedUser);
    await sendAccountBlockedEmail({
      to: user.email,
      reason: "Two devices were signed in to your account at the same time.",
      proofText: renderProofNarrative(report),
      caseId: evidence.recordHash.slice(0, 12),
    });
  } catch (error) {
    console.error("Failed to send block explanation email:", error.message);
  }

  const error = new Error("ACCOUNT_BLOCKED_SHARING");
  error.caseId = evidence.recordHash.slice(0, 12);
  throw error;
};

const blockForSwitchLimit = async (user, context, switches) => {
  const evidence = await appendEvidence({
    user,
    kind: "SWITCH_LIMIT_BLOCKED",
    deviceKey: null,
    payload: {
      observation: context.observation,
      switchesInWindow: switches,
      allowedSwitches: config.device.maxSwitchesPerWindow,
      windowDays: config.device.switchWindowDays,
    },
    narrative:
      `This account changed its authorised device ${switches} times in the last ` +
      `${config.device.switchWindowDays} days, exceeding the limit of ` +
      `${config.device.maxSwitchesPerWindow}. Each of those switches is individually recorded ` +
      "with the device and network it came from.",
  });

  const reason = `Device switch limit exceeded (case ${evidence.recordHash.slice(0, 12)})`;
  const blockedUser = await markUserBlocked(user, reason);
  await revokeAllSessionsForUser(blockedUser, reason);

  await recordSecurityEvent({
    type: "DEVICE_SWITCH_LIMIT_BLOCKED",
    email: user.email,
    deviceId: context.clientDeviceId,
    message: reason,
    user: blockedUser,
    metadata: { caseId: evidence.recordHash.slice(0, 12), switches },
  });

  const error = new Error("ACCOUNT_BLOCKED_SWITCH_LIMIT");
  error.caseId = evidence.recordHash.slice(0, 12);
  throw error;
};

/**
 * Password + device authentication.
 *
 * Unlike the previous implementation, an unrecognised device never blocks on its own. It either
 * matches a known device through its fingerprint (the cleared-cache case), or it goes through
 * email verification. Only provable concurrent use results in a block.
 */
export const authenticateUser = async ({
  email,
  password,
  deviceId,
  deviceLabel,
  fingerprint,
  ipAddress,
  headers,
}) => {
  const user = await findUserByEmail(email);
  if (!user) {
    await recordSecurityEvent({
      type: "FAILED_LOGIN",
      email,
      deviceId,
      message: "Invalid credentials",
    });
    throw new Error("INVALID_CREDENTIALS");
  }

  if (user.blocked) {
    await addAuditEvent(user, "AUTH_FAILURE", "Blocked account attempted login");
    await recordSecurityEvent({
      type: "BLOCKED_LOGIN",
      email,
      deviceId,
      message: "Blocked user attempted login",
      user,
    });
    throw new Error("ACCOUNT_BLOCKED");
  }

  const matches = await bcrypt.compare(password, user.passwordHash);
  if (!matches) {
    await addAuditEvent(user, "AUTH_FAILURE", "Wrong password");
    await recordSecurityEvent({
      type: "FAILED_LOGIN",
      email,
      deviceId,
      message: "Invalid credentials",
      user,
    });
    throw new Error("INVALID_CREDENTIALS");
  }

  const context = await buildDeviceContext({
    fingerprint,
    clientDeviceId: deviceId,
    ip: ipAddress,
    headers,
  });

  // Administrators are exempt from device binding so support can always get in.
  if (user.isAdmin) {
    const result = await issueSession(user, context, null, deviceLabel);
    return { user, session: result.session, reused: result.reused, rotated: Boolean(result.rotated) };
  }

  const evaluation = await evaluateLogin(user, context);

  if (evaluation.decision === "block") {
    if (evaluation.reason === "SWITCH_LIMIT") {
      return blockForSwitchLimit(user, context, evaluation.switches);
    }
    return blockForConcurrentUse(user, context, evaluation.concurrency);
  }

  if (evaluation.decision === "verify") {
    const challenge = await issueDeviceChallenge(user, evaluation.device, context);
    await addAuditEvent(
      user,
      "DEVICE_VERIFICATION_REQUIRED",
      `Verification required for ${evaluation.device.label}`,
    );
    return {
      user,
      requiresDeviceVerification: true,
      challengeId: challenge.challengeId,
      expiresAt: challenge.expiresAt,
      deviceLabel: evaluation.device.label,
      maskedEmail: user.email.replace(/^(.).*(@.*)$/, (_m, a, b) => `${a}${"*".repeat(5)}${b}`),
    };
  }

  const result = await issueSession(user, context, evaluation.device, deviceLabel);

  await appendEvidence({
    user,
    kind: "DEVICE_OBSERVED",
    deviceKey: evaluation.device.deviceKey,
    payload: {
      observation: context.observation,
      matchType: evaluation.matchType,
      matchScore: evaluation.score,
      sessionId: String(result.session._id),
      reason: "successful_login_on_trusted_device",
    },
    narrative: `Signed in on the authorised device ${evaluation.device.label}.`,
  });

  await recordSecurityEvent({
    type: "LOGIN_SUCCESS",
    email,
    deviceId,
    deviceKey: evaluation.device.deviceKey,
    message: result.reused ? "Session reused" : result.rotated ? "Session rotated" : "Session created",
    user,
    metadata: { matchType: evaluation.matchType, ipAddress: context.geo?.ip },
  });

  return {
    user,
    session: result.session,
    reused: result.reused,
    rotated: Boolean(result.rotated),
    deviceKey: evaluation.device.deviceKey,
  };
};

/**
 * Second step of a new-device login: redeem the emailed code, trust the device, deauthorise the
 * previous one, and issue the session.
 */
export const completeDeviceVerification = async ({
  email,
  challengeId,
  code,
  deviceId,
  deviceLabel,
  fingerprint,
  ipAddress,
  headers,
}) => {
  const user = await findUserByEmail(email);
  if (!user) throw new Error("INVALID_CREDENTIALS");
  if (user.blocked) throw new Error("ACCOUNT_BLOCKED");

  const context = await buildDeviceContext({
    fingerprint,
    clientDeviceId: deviceId,
    ip: ipAddress,
    headers,
  });
  const { buildObservation } = await import("./evidenceService.js");
  context.observation = buildObservation(context);

  const result = await verifyDeviceChallenge({ user, challengeId, code, context });
  if (!result.ok) {
    const error = new Error(result.error);
    error.attemptsRemaining = result.attemptsRemaining;
    throw error;
  }

  const replaced = await demoteOtherDevices(user, result.device.deviceKey, context);

  await recordObservation(result.device, context, {
    matchType: "verified",
    score: 1,
    countLogin: false,
  });

  const session = await issueSession(user, context, result.device, deviceLabel);

  if (replaced.length > 0) {
    try {
      await sendDeviceSwitchNotice({
        to: user.email,
        newDevice: result.device,
        replacedDevices: replaced,
        context,
      });
    } catch (error) {
      console.error("Failed to send device switch notice:", error.message);
    }
  }

  await recordSecurityEvent({
    type: "DEVICE_VERIFIED",
    email: user.email,
    deviceId,
    deviceKey: result.device.deviceKey,
    message: "New device authorised by email code",
    user,
    metadata: {
      replacedDevices: replaced.map((device) => device.deviceKey),
      ipAddress: context.geo?.ip,
    },
  });

  return {
    user,
    session: session.session,
    deviceKey: result.device.deviceKey,
    replacedDevices: replaced.map((device) => device.label),
  };
};

export const invalidateSessionByToken = async (token, reason) => {
  const session = await findSessionByToken(token);
  if (!session) return null;
  await revokeSession(session, reason);
  await recordSecurityEvent({
    type: "LOGOUT",
    email: session.user?.email,
    deviceId: session.deviceId,
    deviceKey: session.deviceKey,
    message: reason,
    user: session.user,
  });
  return session;
};

export const getSessionFromToken = async (token) => {
  const session = await findSessionByToken(token);
  if (!session) return null;
  const user = session.user;
  if (!user || user.blocked) {
    await revokeSession(session, "User blocked during session validation");
    throw new Error("ACCOUNT_BLOCKED");
  }
  return { session, user };
};

/**
 * Called by the client heartbeat. Keeps `lastSeenAt` current - which is what makes concurrency
 * detection reliable - and re-checks that the session is still on its authorised device.
 */
export const heartbeatSession = async ({ token, fingerprint, deviceId, ipAddress, headers }) => {
  const result = await getSessionFromToken(token);
  if (!result) return { ok: false, error: "INVALID_SESSION" };

  const { session, user } = result;
  if (user.isAdmin) {
    await touchSession(session);
    return { ok: true, heartbeatSeconds: config.device.heartbeatSeconds };
  }

  const context = await buildDeviceContext({
    fingerprint,
    clientDeviceId: deviceId,
    ip: ipAddress,
    headers,
  });
  const { buildObservation } = await import("./evidenceService.js");
  context.observation = buildObservation(context);

  const match = await matchDevice(user, context);

  // The session token is being used from a device that is not the one it was issued to. That is
  // a shared token, and it is recorded with both fingerprints.
  if (session.deviceKey && (!match.device || match.device.deviceKey !== session.deviceKey)) {
    const sessionDevice = await DeviceModel.findOne({
      user: user._id,
      deviceKey: session.deviceKey,
    }).lean();

    if (sessionDevice) {
      const { compareDevices } = await import("./evidenceService.js");
      const comparison = compareDevices(context.signals, sessionDevice.signals ?? {});

      /**
       * A mid-session block is the most damaging kind of false positive, so this needs more than
       * a similarity dip. It requires all three of:
       *   - a rich fingerprint (not a browser hiding its signals),
       *   - similarity below the same-device threshold, and
       *   - a measurable hardware-class difference, i.e. a different OS, GPU or screen.
       * A driver update or browser upgrade shifts similarity but never hardware class, so those
       * cannot trip this. A genuinely different machine presenting the same token does.
       */
      if (
        context.confidence >= config.device.minConfidence &&
        comparison.similarity < config.device.matchThreshold &&
        comparison.differentHardwareClass
      ) {
        const evidence = await appendEvidence({
          user,
          kind: "CONCURRENT_USE_BLOCKED",
          deviceKey: session.deviceKey,
          payload: {
            observation: context.observation,
            sharingScore: 100,
            threshold: config.device.blockScore,
            factors: [
              {
                factor: "session_token_used_from_different_device",
                weight: 100,
                detail:
                  "The same session token was presented from a device whose measured hardware " +
                  "differs from the device the session was issued to.",
              },
            ],
            comparison,
            overlap: {
              minutesApart: 0,
              otherDeviceLastSeenAt: session.lastSeenAt,
              incomingAt: new Date().toISOString(),
            },
            existingDevice: {
              deviceKey: sessionDevice.deviceKey,
              deviceDescription: sessionDevice.label,
              signals: sessionDevice.signals,
              lastSeenAt: sessionDevice.lastSeenAt,
            },
            incomingDevice: {
              deviceDescription: context.observation.deviceDescription,
              signals: context.signals,
              observedAt: context.observation.observedAt,
              ip: context.observation.network.ip,
              isp: context.observation.network.isp,
              city: context.observation.network.city,
              country: context.observation.network.country,
            },
          },
          narrative:
            `An active session issued to ${sessionDevice.label} was used from ` +
            `${context.observation.deviceDescription}. The session token was shared between two ` +
            "physically different devices.",
        });

        const reason = `Session token shared between devices (case ${evidence.recordHash.slice(0, 12)})`;
        const blockedUser = await markUserBlocked(user, reason);
        await revokeAllSessionsForUser(blockedUser, reason);

        try {
          const report = await buildSharingReport(blockedUser);
          await sendAccountBlockedEmail({
            to: user.email,
            reason: "Your session was used from two different devices.",
            proofText: renderProofNarrative(report),
            caseId: evidence.recordHash.slice(0, 12),
          });
        } catch (error) {
          console.error("Failed to send block explanation email:", error.message);
        }

        return { ok: false, error: "ACCOUNT_BLOCKED_SHARING", caseId: evidence.recordHash.slice(0, 12) };
      }
    }
  }

  if (match.device) {
    await recordObservation(match.device, context, {
      matchType: match.matchType,
      score: match.score,
    });
  }

  await touchSession(session);
  return { ok: true, heartbeatSeconds: config.device.heartbeatSeconds };
};

export const seedDefaultUser = async () => {
  const email = "chahandesanket4@gmail.com";
  const password = "Trade!2025";
  await ensureUserExists(email, password, { isAdmin: true });
};

/**
 * NOTE: `blockUserForDevtools` was removed deliberately.
 *
 * It blocked an account permanently the moment the browser posted a devtools report, with no
 * corroboration and nothing recorded that could be reviewed afterwards. The client-side
 * heuristics feeding it fired on browser zoom, split screen, device rotation and slow animation
 * frames, so honest users lost their accounts and support had nothing to show them.
 *
 * Inspection reports now go through services/inspectionService.js, which scores them by signal
 * reliability, writes them to the signed evidence chain, and by default leaves the decision to a
 * human (DEVTOOLS_POLICY=review). Blocking requires several independently corroborated reports.
 */
