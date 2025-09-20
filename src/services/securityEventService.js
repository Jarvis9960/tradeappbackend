import { SecurityEventModel } from "../models/SecurityEvent.js";

export const recordSecurityEvent = async (params) => {
  const doc = new SecurityEventModel({
    type: params.type,
    message: params.message,
    email: params.email?.toLowerCase(),
    deviceId: params.deviceId,
    user: params.user?._id,
    metadata: params.metadata,
  });
  await doc.save();
};