import mongoose, { Schema } from "mongoose";

const SessionSchema = new Schema(
  {
    token: { type: String, required: true, unique: true, index: true },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },

    /** Legacy client-generated id. Kept so old sessions keep working. */
    deviceId: { type: String, required: true },

    /** Stable key of the physical device (Device.deviceKey). Drives concurrency detection. */
    deviceKey: { type: String, index: true },

    deviceLabel: { type: String },

    createdAt: { type: Date, default: () => new Date() },

    /**
     * Updated by the client heartbeat. A session is only "in use" if its heartbeat is recent,
     * which is what lets us distinguish a genuinely concurrent second device from a stale
     * session the user simply never logged out of.
     */
    lastSeenAt: { type: Date, default: () => new Date(), index: true },

    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, index: true },
    revokedReason: { type: String },
  },
  { timestamps: false },
);

SessionSchema.index({ user: 1, revokedAt: 1 });
SessionSchema.index({ user: 1, lastSeenAt: -1 });
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const SessionModel = mongoose.models.Session || mongoose.model("Session", SessionSchema);
