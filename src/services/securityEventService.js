import { SecurityEventModel } from "../models/SecurityEvent.js";
import { sendSecurityNotification } from "./emailService.js";

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
  
  // Send email notification for critical security events
  if (params.type === "DEVTOOLS_OPENED" || params.type === "SECOND_DEVICE_ATTEMPT") {
    const subject = `Security Alert: ${params.type}`;
    const text = `A security event has been detected in the Trade App.\n\nEvent: ${params.type}\nUser: ${params.email || 'Unknown'}\nMessage: ${params.message}`;
    
    try {
      await sendSecurityNotification({ subject, text, eventData: params });
    } catch (error) {
      console.error("Failed to send security notification email:", error);
    }
  }
};