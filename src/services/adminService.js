import bcrypt from "bcryptjs";
import { UserModel } from "../models/User.js";
import { SessionModel } from "../models/Session.js";
import { SecurityEventModel } from "../models/SecurityEvent.js";
import {
  addAuditEvent,
  createUser,
  findUserByEmail,
  findUserById,
  markUserBlocked,
  unblockUser,
  updateUserCredits,
} from "./userService.js";
import {
  findSessionById,
  revokeAllSessionsForUser,
  revokeSession,
} from "./sessionService.js";
import { recordSecurityEvent } from "./securityEventService.js";

const sanitizeUser = (userLike) => {
  if (!userLike) return null;
  const user = userLike.toObject ? userLike.toObject({ versionKey: false }) : { ...userLike };
  delete user.passwordHash;
  return user;
};

export const getAdminStats = async () => {
  const now = new Date();
  const [totalUsers, blockedUsers, activeUsers, activeSessions] = await Promise.all([
    UserModel.countDocuments({}),
    UserModel.countDocuments({ blocked: true }),
    UserModel.countDocuments({ blocked: false }),
    SessionModel.countDocuments({ revokedAt: { $exists: false }, expiresAt: { $gt: now } }),
  ]);

  return {
    totalUsers,
    blockedUsers,
    activeUsers,
    activeSessions,
  };
};

export const listUsersForAdmin = async () => {
  const users = await UserModel.find({}).sort({ createdAt: -1 }).lean();
  return users.map(({ passwordHash, __v, ...rest }) => rest);
};

export const createUserForAdmin = async ({ email, password, credits = 0 }) => {
  const existing = await findUserByEmail(email);
  if (existing) {
    const error = new Error("User already exists");
    error.statusCode = 409;
    error.code = "USER_EXISTS";
    throw error;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await createUser({ email, passwordHash, credits });
  await addAuditEvent(user, "ACCOUNT_CREATED", "User created by administrator");
  await recordSecurityEvent({
    type: "ADMIN_USER_CREATED",
    email: user.email,
    message: "Administrator created user",
    user,
  });
  return sanitizeUser(user);
};

export const blockUserForAdmin = async (userId, reason) => {
  const user = await findUserById(userId);
  if (!user) {
    const error = new Error("User not found");
    error.statusCode = 404;
    error.code = "USER_NOT_FOUND";
    throw error;
  }

  const message = reason?.trim() || "Blocked by administrator";
  await revokeAllSessionsForUser(user, message);
  const blockedUser = await markUserBlocked(user, message);
  await recordSecurityEvent({
    type: "ADMIN_BLOCK",
    email: blockedUser.email,
    message,
    user: blockedUser,
  });
  return sanitizeUser(blockedUser);
};

export const unblockUserForAdmin = async (userId, reason) => {
  const user = await findUserById(userId);
  if (!user) {
    const error = new Error("User not found");
    error.statusCode = 404;
    error.code = "USER_NOT_FOUND";
    throw error;
  }

  const message = reason?.trim() || "Unblocked by administrator";
  const updatedUser = await unblockUser(user, message);
  await recordSecurityEvent({
    type: "ADMIN_UNBLOCK",
    email: updatedUser.email,
    message,
    user: updatedUser,
  });
  return sanitizeUser(updatedUser);
};

export const updateCreditsForAdmin = async (userId, credits) => {
  const user = await findUserById(userId);
  if (!user) {
    const error = new Error("User not found");
    error.statusCode = 404;
    error.code = "USER_NOT_FOUND";
    throw error;
  }

  const updatedUser = await updateUserCredits(
    user,
    credits,
    `Credits adjusted to ${credits} by administrator`,
  );
  await recordSecurityEvent({
    type: "ADMIN_CREDITS_UPDATE",
    email: updatedUser.email,
    message: `Credits set to ${credits} by administrator`,
    user: updatedUser,
  });
  return sanitizeUser(updatedUser);
};

export const listSessionsForAdmin = async ({ includeRevoked = true, limit = 100 } = {}) => {
  const now = new Date();
  const query = includeRevoked ? {} : { revokedAt: { $exists: false }, expiresAt: { $gt: now } };

  const sessions = await SessionModel.find(query)
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("user", "email blocked credits");

  return sessions.map((session) => {
    const doc = session.toObject({ versionKey: false });
    if (doc.user) {
      delete doc.user.passwordHash;
    }
    return doc;
  });
};

export const revokeSessionForAdmin = async (sessionId, reason) => {
  const session = await findSessionById(sessionId);
  if (!session) {
    const error = new Error("Session not found");
    error.statusCode = 404;
    error.code = "SESSION_NOT_FOUND";
    throw error;
  }

  const message = reason?.trim() || "Session revoked by administrator";
  await revokeSession(session, message);
  await recordSecurityEvent({
    type: "ADMIN_SESSION_REVOKE",
    email: session.user?.email,
    deviceId: session.deviceId,
    message,
    user: session.user,
  });
};

export const listSecurityEventsForAdmin = async (limit = 50) => {
  const events = await SecurityEventModel.find({})
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate("user", "email blocked");

  return events.map((event) => {
    const doc = event.toObject({ versionKey: false });
    if (doc.user) {
      delete doc.user.passwordHash;
    }
    return doc;
  });
};
