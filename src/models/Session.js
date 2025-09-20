import mongoose, { Schema } from "mongoose";

const SessionSchema = new Schema(
  {
    token: { type: String, required: true, unique: true, index: true },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    deviceId: { type: String, required: true },
    deviceLabel: { type: String },
    createdAt: { type: Date, default: () => new Date() },
    expiresAt: { type: Date, required: true, index: true },
    revokedAt: { type: Date, index: true },
    revokedReason: { type: String },
  },
  { timestamps: false },
);

SessionSchema.index({ user: 1, revokedAt: 1 });
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const SessionModel = mongoose.models.Session || mongoose.model("Session", SessionSchema);