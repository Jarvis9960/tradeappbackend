import { addAuditEvent } from "./userService.js";
import { SessionModel } from "../models/Session.js";
import { generateToken } from "../utils/token.js";
import { config } from "../config.js";

const ttlMinutes = () => config.sessionTtlMinutes;

const computeExpiry = () => {
  const expires = new Date();
  expires.setMinutes(expires.getMinutes() + ttlMinutes());
  return expires;
};

export const findActiveSessionForUser = async (user) =>
  SessionModel.findOne({
    user: user._id,
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  });

export const findSessionByToken = async (token) =>
  SessionModel.findOne({
    token,
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  }).populate("user");

export const findSessionById = async (id) => SessionModel.findById(id).populate("user");

/** Heartbeat touch. Also slides the expiry forward so active users are not logged out mid-session. */
export const touchSession = async (session) => {
  const now = new Date();
  await SessionModel.updateOne(
    { _id: session._id },
    { $set: { lastSeenAt: now, expiresAt: computeExpiry() } },
  );
  session.lastSeenAt = now;
  return session;
};

export const revokeSession = async (session, reason) => {
  session.revokedAt = new Date();
  session.revokedReason = reason;
  const populated = await session.populate("user");
  await session.save();
  if (populated.user) {
    await addAuditEvent(populated.user, "SESSION_TERMINATED", reason);
  }
};

export const revokeAllSessionsForUser = async (user, reason) => {
  const sessions = await SessionModel.find({ user: user._id, revokedAt: { $exists: false } });
  await Promise.all(
    sessions.map(async (session) => {
      session.revokedAt = new Date();
      session.revokedReason = reason;
      await session.save();
    }),
  );
  await addAuditEvent(user, "SESSION_TERMINATED", reason);
};

/**
 * Issue a session for a device, enforcing one live session per account.
 *
 * Sessions are keyed on the physical device (`deviceKey`), not on the disposable client id, so a
 * user whose browser storage was wiped resumes their existing session instead of displacing it
 * and looking like a second device.
 */
export const issueSession = async (user, context, device, deviceLabel) => {
  const deviceKey = device?.deviceKey ?? null;
  const clientDeviceId = context?.clientDeviceId ?? "unknown";
  const label = deviceLabel ?? device?.label ?? context?.observation?.deviceDescription;

  const activeSessions = await SessionModel.find({
    user: user._id,
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  });

  const sameDeviceSession = activeSessions.find((session) =>
    deviceKey ? session.deviceKey === deviceKey : session.deviceId === clientDeviceId,
  );

  if (sameDeviceSession) {
    const otherSessions = activeSessions.filter((session) => session.id !== sameDeviceSession.id);

    sameDeviceSession.expiresAt = computeExpiry();
    sameDeviceSession.lastSeenAt = new Date();
    sameDeviceSession.deviceId = clientDeviceId;
    if (deviceKey) sameDeviceSession.deviceKey = deviceKey;
    if (label && sameDeviceSession.deviceLabel !== label) {
      sameDeviceSession.deviceLabel = label;
    }
    await sameDeviceSession.save();
    await addAuditEvent(user, "AUTH_SUCCESS", "Session reused");

    if (otherSessions.length > 0) {
      await Promise.all(
        otherSessions.map((session) =>
          revokeSession(session, "Revoked to enforce single active session"),
        ),
      );
    }
    return { session: sameDeviceSession, reused: true };
  }

  if (activeSessions.length > 0) {
    await Promise.all(
      activeSessions.map((session) =>
        revokeSession(session, "Revoked before issuing new session"),
      ),
    );
  }

  const session = new SessionModel({
    token: generateToken(),
    user: user._id,
    deviceId: clientDeviceId,
    deviceKey,
    deviceLabel: label,
    createdAt: new Date(),
    lastSeenAt: new Date(),
    expiresAt: computeExpiry(),
  });
  await session.save();
  await addAuditEvent(
    user,
    "AUTH_SUCCESS",
    activeSessions.length > 0 ? "Session issued on new device" : "Session issued",
  );
  return { session, reused: false, rotated: activeSessions.length > 0 };
};
