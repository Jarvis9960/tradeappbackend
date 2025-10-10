import bcrypt from "bcryptjs";
import { findUserByEmail, addAuditEvent, createUser, markUserBlocked } from "./userService.js";
import {
  issueSession,
  findSessionByToken,
  revokeSession,
  revokeAllSessionsForUser,
} from "./sessionService.js";
import { recordSecurityEvent } from "./securityEventService.js";

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

export const authenticateUser = async (
  email,
  password,
  deviceId,
  deviceLabel,
) => {
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

  const result = await issueSession(user, deviceId, deviceLabel);
  await recordSecurityEvent({
    type: "LOGIN_SUCCESS",
    email,
    deviceId,
    message: result.reused ? "Session reused" : result.rotated ? "Session rotated" : "Session created",
    user,
  });
  return {
    user,
    session: result.session,
    reused: result.reused,
    rotated: Boolean(result.rotated),
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

export const seedDefaultUser = async () => {
  const email = "chahandesanket4@gmail.com";
  const password = "Trade!2025";
  await ensureUserExists(email, password, { isAdmin: true });
};

export const blockUserForDevtools = async (user, deviceId, message) => {
  await revokeAllSessionsForUser(user, message ?? "Sessions revoked after devtools alert");
  await markUserBlocked(user, message ?? "Developer tools detected");
  await recordSecurityEvent({
    type: "DEVTOOLS_OPENED",
    email: user.email,
    deviceId,
    message: message ?? "Developer tools detected on client",
    user,
  });
};
