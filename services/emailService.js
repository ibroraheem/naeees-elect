const nodemailer = require('nodemailer');

const requiredEnvironmentVariables = ['ZOHO_USER', 'ZOHO_APP_PASSWORD'];

function getEmailConfiguration() {
  const missing = requiredEnvironmentVariables.filter((name) => !process.env[name]);

  if (missing.length) {
    throw new Error(`Zoho SMTP configuration is missing: ${missing.join(', ')}`);
  }

  const port = Number(process.env.ZOHO_SMTP_PORT || 465);
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error('ZOHO_SMTP_PORT must be a valid port number');
  }

  return {
    host: process.env.ZOHO_SMTP_HOST || 'smtp.zoho.com',
    port,
    secure: process.env.ZOHO_SMTP_SECURE
      ? process.env.ZOHO_SMTP_SECURE === 'true'
      : port === 465,
    user: process.env.ZOHO_USER,
    password: process.env.ZOHO_APP_PASSWORD,
    from: process.env.ZOHO_FROM || process.env.ZOHO_USER
  };
}

const sendOtp = async (to, subject, html) => {
  const config = getEmailConfiguration();
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: {
      user: config.user,
      pass: config.password
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });

  try {
    const info = await transporter.sendMail({
      from: `NAEEES Elections <${config.from}>`,
      to,
      subject,
      html
    });

    if (!info.accepted.length) {
      throw new Error(`Zoho rejected the recipient: ${info.rejected.join(', ')}`);
    }

    return {
      success: true,
      service: 'Zoho SMTP',
      data: { messageId: info.messageId, accepted: info.accepted }
    };
  } catch (error) {
    console.error('[Zoho SMTP] Email request failed:', {
      code: error.code,
      responseCode: error.responseCode,
      command: error.command,
      message: error.message
    });
    throw error;
  }
};

module.exports = { sendOtp };