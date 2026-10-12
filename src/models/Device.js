import mongoose, { Schema } from "mongoose";

/**
 * One document per *physical device* per user.
 *
 * The key difference from the old `user.devices` array: a device is not identified by a single
 * disposable id. It accumulates every client id, every strict fingerprint and every hardware
 * hash we have ever seen for the same machine. When a user clears storage, the incoming
 * fingerprint still matches an entry here, we attach the new client id to this same document,
 * and nothing is treated as a new device.
 */

const ObservedIpSchema = new Schema(
  {
    ip: { type: String, required: true },
    asn: { type: String },
    isp: { type: String },
    city: { type: String },
    region: { type: String },
    country: { type: String },
    latitude: { type: Number },
    longitude: { type: Number },
    firstSeenAt: { type: Date, default: () => new Date() },
    lastSeenAt: { type: Date, default: () => new Date() },
    hitCount: { type: Number, default: 1 },
  },
  { _id: false },
);

const FingerprintObservationSchema = new Schema(
  {
    strictHash: { type: String, required: true },
    hardwareHash: { type: String, required: true },
    signals: { type: Schema.Types.Mixed, required: true },
    confidence: { type: Number },
    capturedAt: { type: Date, default: () => new Date() },
  },
  { _id: false },
);

const DeviceSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },

    /** Our stable handle for this physical device. Never changes once assigned. */
    deviceKey: { type: String, required: true, unique: true, index: true },

    /** Every client-side id this device has ever presented (one per storage wipe). */
    clientIds: { type: [String], default: [], index: true },

    /** Every full fingerprint hash seen (one per browser, plus one per browser major change). */
    strictHashes: { type: [String], default: [], index: true },

    /** Every hardware-only hash seen. Usually one; more after a hardware/driver change. */
    hardwareHashes: { type: [String], default: [], index: true },

    /** Most recent canonical signals, used for similarity matching against new logins. */
    signals: { type: Schema.Types.Mixed },

    label: { type: String },
    platform: { type: String, index: true },

    /**
     * A device becomes trusted when the user proves ownership with the emailed code. Only a
     * trusted device may hold a session, which is what enforces single-device access.
     */
    trusted: { type: Boolean, default: false, index: true },
    verifiedAt: { type: Date },
    verificationMethod: { type: String },

    /** Kept for the audit trail: how we recognised this device on the most recent login. */
    lastMatchType: { type: String },
    lastMatchScore: { type: Number },

    firstSeenAt: { type: Date, default: () => new Date() },
    lastSeenAt: { type: Date, default: () => new Date(), index: true },
    loginCount: { type: Number, default: 0 },

    observedIps: { type: [ObservedIpSchema], default: [] },

    /** Bounded history, newest first. Used to build the proof report. */
    fingerprintHistory: { type: [FingerprintObservationSchema], default: [] },

    revokedAt: { type: Date },
    revokedReason: { type: String },
  },
  { timestamps: true },
);

DeviceSchema.index({ user: 1, revokedAt: 1, lastSeenAt: -1 });
DeviceSchema.index({ user: 1, trusted: 1 });

export const DeviceModel = mongoose.models.Device || mongoose.model("Device", DeviceSchema);
