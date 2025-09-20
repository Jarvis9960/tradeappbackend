import { randomBytes } from "crypto";

export const generateToken = (lengthBytes = 32) => randomBytes(lengthBytes).toString("hex");