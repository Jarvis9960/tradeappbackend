import mongoose, { Schema } from "mongoose";

const AuditEventSchema = new Schema(
  {
    type: { type: String, required: true },
    detail: { type: String },
    createdAt: { type: Date, default: () => new Date(), index: true },
  },
  { _id: true },
);

const UserSchema = new Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, index: true },
    passwordHash: { type: String, required: true },
    blocked: { type: Boolean, default: false, index: true },
    blockedReason: { type: String },
    blockedAt: { type: Date },
    credits: { type: Number, default: 0, min: 0 },
    isAdmin: { type: Boolean, default: false, index: true },
    devices: {
      type: [
        {
          deviceId: { type: String, required: true },
          deviceLabel: { type: String },
          firstSeenAt: { type: Date, default: () => new Date() },
          lastSeenAt: { type: Date, default: () => new Date() },
          lastIp: { type: String },
        },
      ],
      default: [],
    },
    auditTrail: { type: [AuditEventSchema], default: [] },
  },
  { timestamps: true },
);

export const UserModel = mongoose.models.User || mongoose.model("User", UserSchema);
