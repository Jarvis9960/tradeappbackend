import { UserModel } from "../models/User.js";

const AUDIT_LIMIT = 100;

const pushAudit = async (user, event) => {
  const auditEntry = {
    type: event.type,
    detail: event.detail,
    createdAt: new Date(),
  };

  await UserModel.updateOne(
    { _id: user._id },
    {
      $push: {
        auditTrail: {
          $each: [auditEntry],
          $position: 0,
          $slice: AUDIT_LIMIT,
        },
      },
    },
  );

  user.auditTrail.unshift(auditEntry);
  if (user.auditTrail.length > AUDIT_LIMIT) {
    user.auditTrail.length = AUDIT_LIMIT;
  }
};

export const addAuditEvent = async (user, type, detail) => {
  await pushAudit(user, { type, detail });
};

/**
 * NOTE: `upsertAllowedDevice` was removed deliberately.
 *
 * It identified a device by a single client-generated id and flagged any previously unseen id
 * as account sharing (`shouldFlagSharing = devices.length > 0`). Because that id lived only in
 * localStorage, clearing browser data, using a private window, or iOS Safari evicting storage
 * after seven days all produced a new id and permanently blocked an innocent user - with no
 * evidence that could tell that case apart from genuine sharing.
 *
 * Device identity now lives in models/Device.js and services/deviceService.js, which match on a
 * hardware/browser fingerprint and only ever block on provable concurrent use.
 */

export const markUserBlocked = async (user, reason) => {
  const blockedAt = new Date();
  await UserModel.updateOne(
    { _id: user._id },
    {
      $set: {
        blocked: true,
        blockedReason: reason,
        blockedAt,
      },
    },
  );
  const updatedUser = await UserModel.findById(user._id);
  await pushAudit(updatedUser, { type: "ACCOUNT_BLOCKED", detail: reason });
  return updatedUser;
};

export const findUserByEmail = async (email) => UserModel.findOne({ email: email.toLowerCase() });

export const createUser = async (params) => {
  const user = new UserModel({
    email: params.email,
    passwordHash: params.passwordHash,
    credits: params.credits ?? 0,
    isAdmin: params.isAdmin ?? false,
  });
  await user.save();
  return user;
};

export const findUserById = async (id) => UserModel.findById(id);

export const unblockUser = async (user, reason) => {
  await UserModel.updateOne(
    { _id: user._id },
    {
      $set: {
        blocked: false,
        blockedReason: null,
        blockedAt: null,
      },
    },
  );
  const updatedUser = await UserModel.findById(user._id);
  await pushAudit(updatedUser, {
    type: "ACCOUNT_UNBLOCKED",
    detail: reason ?? "User unblocked by administrator",
  });
  return updatedUser;
};

export const updateUserCredits = async (user, credits, detailContext) => {
  await UserModel.updateOne(
    { _id: user._id },
    {
      $set: {
        credits,
      },
    },
  );
  const updatedUser = await UserModel.findById(user._id);
  await pushAudit(updatedUser, {
    type: "CREDITS_UPDATED",
    detail: detailContext ?? `Credits set to ${credits}`,
  });
  return updatedUser;
};

