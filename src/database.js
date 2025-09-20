import mongoose from "mongoose";
import { config } from "./config.js";

export const connectDatabase = async () => {
  if (mongoose.connection.readyState === 1) return;
  await mongoose.connect(config.mongodbUri);
};

export const disconnectDatabase = async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
};