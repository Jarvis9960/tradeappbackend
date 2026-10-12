import mongoose, { Schema } from "mongoose";

/**
 * Append-only, hash-chained evidence log.
 *
 * Nothing in here is ever updated or deleted. `payload` holds the complete observation that was
 * hashed; `prevHash`/`recordHash`/`signature` chain and sign it (see utils/evidenceChain.js).
 * When a user says "I never used a second device", this collection is the answer: it holds the
 * raw signals from both devices, the timestamps, the networks, and a signature proving the
 * records were written at the time and not edited since.
 */

const DeviceEvidenceSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    email: { type: String, index: true },

    /** Per-user monotonic sequence number. Gaps or reordering break chain verification. */
    seq: { type: Number, required: true },

    /**
     * DEVICE_OBSERVED        - a login or heartbeat, with the full fingerprint snapshot
     * DEVICE_REGISTERED      - first ever device, trusted without challenge
     * DEVICE_RECOGNIZED      - fingerprint matched a known device after a storage wipe
     * VERIFICATION_SENT      - emailed code issued for a new device
     * VERIFICATION_PASSED    - user proved ownership of a new device
     * VERIFICATION_FAILED    - wrong or expired code
     * DEVICE_SWITCHED        - trusted device replaced after verification
     * CONCURRENT_USE_BLOCKED - two devices provably in use at once
     * SWITCH_LIMIT_BLOCKED   - too many device switches in the window
     */
    kind: { type: String, required: true, index: true },

    deviceKey: { type: String, index: true },

    /** The exact data that was signed. Treated as immutable. */
    payload: { type: Schema.Types.Mixed, required: true },

    /** Plain-English line, safe to show the end user verbatim. */
    narrative: { type: String },

    prevHash: { type: String, required: true },
    recordHash: { type: String, required: true, unique: true },
    signature: { type: String, required: true },

    recordedAt: { type: Date, default: () => new Date(), index: true },
  },
  { timestamps: false },
);

DeviceEvidenceSchema.index({ user: 1, seq: 1 }, { unique: true });
DeviceEvidenceSchema.index({ user: 1, recordedAt: -1 });

export const DeviceEvidenceModel =
  mongoose.models.DeviceEvidence || mongoose.model("DeviceEvidence", DeviceEvidenceSchema);
