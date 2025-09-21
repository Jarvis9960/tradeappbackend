import nodemailer from 'nodemailer';

// Create a transporter using Gmail with App Password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'ankitfukte11@gmail.com',
    pass: process.env.GOOGLE_PASSWORD, // Google App Password
  }
});

/**
 * Send security notification email
 * @param {Object} params - Email parameters
 * @param {string} params.subject - Email subject
 * @param {string} params.text - Email text content
 * @param {Object} params.eventData - Security event data
 */
export const sendSecurityNotification = async (params) => {
  const { subject, text, eventData } = params;
  
  // Format event data for email
  const eventDetails = `
    Event Type: ${eventData.type}
    Timestamp: ${new Date().toISOString()}
    User Email: ${eventData.email || 'Unknown'}
    Device ID: ${eventData.deviceId || 'Unknown'}
    Message: ${eventData.message || 'No message provided'}
    User Agent: ${eventData.metadata?.userAgent || 'Unknown'}
    IP Address: ${eventData.metadata?.ipAddress || 'Unknown'}
  `;

  const mailOptions = {
    from: 'ankitfukte11@gmail.com',
    to: 'ankittalks10@gmail.com',
    subject: subject,
    text: `${text}\n\nEvent Details:\n${eventDetails}`
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Security notification email sent:', info.messageId);
    return true;
  } catch (error) {
    console.error('Error sending security notification email:', error);
    return false;
  }
};