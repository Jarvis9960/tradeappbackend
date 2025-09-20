import { addAuditEvent, markUserBlocked } from "./userService.js";
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
  const existing = await findActiveSessionForUser(user);
  if (existing) {
    if (existing.deviceId !== deviceId) {
      await revokeSession(existing, "Revoked after second device login attempt");
      await markUserBlocked(user, "Blocked after second device login attempt");
      throw new Error("SECOND_DEVICE");
    }

    existing.expiresAt = computeExpiry();
    await existing.save();
    await addAuditEvent(user, "AUTH_SUCCESS", "Session reused");
    return { session: existing, reused: true };
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
  await addAuditEvent(user, "AUTH_SUCCESS", "Session issued");
  return { session, reused: false };
};