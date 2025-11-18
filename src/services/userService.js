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

export const upsertAllowedDevice = async (user, deviceId, deviceLabel, ipAddress) => {
  const now = new Date();
  const devices = user.devices ?? [];
  const existing = devices.find((device) => device.deviceId === deviceId);

  if (existing) {
    const updateDoc = {
      "devices.$.lastSeenAt": now,
    };
    if (deviceLabel && existing.deviceLabel !== deviceLabel) {
      updateDoc["devices.$.deviceLabel"] = deviceLabel;
    }
    if (ipAddress) {
      updateDoc["devices.$.lastIp"] = ipAddress;
    }
    await UserModel.updateOne(
      { _id: user._id, "devices.deviceId": deviceId },
      { $set: updateDoc },
    );
    return {
      allowed: true,
      isNew: false,
      device: {
        ...existing,
        lastSeenAt: now,
        deviceLabel: deviceLabel ?? existing.deviceLabel,
        lastIp: ipAddress ?? existing.lastIp,
      },
    };
  }

  // If this is a brand new device and we already have at least one device recorded,
  // treat it as sharing and flag for block.
  const shouldFlagSharing = devices.length > 0;

  const newDevice = {
    deviceId,
    deviceLabel,
    firstSeenAt: now,
    lastSeenAt: now,
    lastIp: ipAddress,
  };

  await UserModel.updateOne(
    { _id: user._id },
    { $push: { devices: newDevice } },
  );

  return {
    allowed: true,
    isNew: true,
    device: newDevice,
    shouldFlagSharing,
  };
};

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

