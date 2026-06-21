const axios = require('axios');

const sendOtp = async (to, subject, html) => {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_FROM) {
    throw new Error('Brevo email configuration is missing');
  }

  const response = await axios.post(
    'https://api.brevo.com/v3/smtp/email',
    {
      sender: { email: process.env.BREVO_FROM },
      to: [{ email: to }],
      subject: subject,
      htmlContent: html
    },
    {
      headers: { 'api-key': process.env.BREVO_API_KEY },
      timeout: 5000
    }
  );

  return { success: true, service: 'Brevo', data: response.data };
};

module.exports = { sendOtp };
