import mongoose, { Schema } from "mongoose";

const SecurityEventSchema = new Schema(
  {
    type: { type: String, required: true, index: true },
    email: { type: String, index: true },
    user: { type: Schema.Types.ObjectId, ref: "User", index: true },
    deviceId: { type: String },
    message: { type: String, required: true },
    metadata: { type: Schema.Types.Mixed },
    createdAt: { type: Date, default: () => new Date(), index: true },
  },
  { timestamps: false },
);

export const SecurityEventModel =
  mongoose.models.SecurityEvent || mongoose.model("SecurityEvent", SecurityEventSchema);