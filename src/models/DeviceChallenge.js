import mongoose, { Schema } from "mongoose";

/**
 * A pending "verify this new device" email challenge.
 *
 * The code is stored hashed, so a database leak cannot be replayed into a device takeover.
 * Challenges are short-lived and attempt-limited, and expire out of the collection on their own.
 */

const DeviceChallengeSchema = new Schema(
  {
    challengeId: { type: String, required: true, unique: true, index: true },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    deviceKey: { type: String, required: true },

    codeHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    maxAttempts: { type: Number, required: true },

    /** Snapshot of the login context, re-checked on verify so the code cannot be used elsewhere. */
    clientDeviceId: { type: String },
    strictHash: { type: String },
    ip: { type: String },

    consumedAt: { type: Date },
    createdAt: { type: Date, default: () => new Date() },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: false },
);

DeviceChallengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const DeviceChallengeModel =
  mongoose.models.DeviceChallenge || mongoose.model("DeviceChallenge", DeviceChallengeSchema);
