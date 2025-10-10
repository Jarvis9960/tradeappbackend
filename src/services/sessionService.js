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
  SessionModel.findOne({ user: user._id, revokedAt: { $exists: false }, expiresAt: { $gt: new Date() } });

export const findSessionByToken = async (token) =>
  SessionModel.findOne({ token, revokedAt: { $exists: false }, expiresAt: { $gt: new Date() } }).populate("user");

export const findSessionById = async (id) => SessionModel.findById(id).populate("user");
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

export const issueSession = async (
  user,
  deviceId,
  deviceLabel,
) => {
  const activeSessions = await SessionModel.find({
    user: user._id,
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  });

  const sameDeviceSession = activeSessions.find((session) => session.deviceId === deviceId);

  if (sameDeviceSession) {
    const otherSessions = activeSessions.filter((session) => session.id !== sameDeviceSession.id);
    sameDeviceSession.expiresAt = computeExpiry();
    if (deviceLabel && sameDeviceSession.deviceLabel !== deviceLabel) {
      sameDeviceSession.deviceLabel = deviceLabel;
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
    deviceId,
    deviceLabel,
    createdAt: new Date(),
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
