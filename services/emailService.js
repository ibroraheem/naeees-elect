const axios = require('axios');

const requiredEnvironmentVariables = [
  'GMAIL_CLIENT_ID',
  'GMAIL_CLIENT_SECRET',
  'GMAIL_REFRESH_TOKEN',
  'GMAIL_USER'
];

function validateEmailConfiguration() {
  const missing = requiredEnvironmentVariables.filter((name) => !process.env[name]);

  if (missing.length) {
    throw new Error(`Gmail API configuration is missing: ${missing.join(', ')}`);
  }
}

async function getAccessToken() {
  const body = new URLSearchParams({
    client_id: process.env.GMAIL_CLIENT_ID,
    client_secret: process.env.GMAIL_CLIENT_SECRET,
    refresh_token: process.env.GMAIL_REFRESH_TOKEN,
    grant_type: 'refresh_token'
  });

  const response = await axios.post(
    'https://oauth2.googleapis.com/token',
    body.toString(),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000
    }
  );

  return response.data.access_token;
}

function encodeHeader(value) {
  return `=?UTF-8?B?${Buffer.from(value).toString('base64')}?=`;
}

function buildRawEmail(to, subject, html) {
  if (/\r|\n/.test(to)) {
    throw new Error('Invalid recipient email address');
  }

  const htmlBase64 = Buffer.from(html)
    .toString('base64')
    .match(/.{1,76}/g)
    .join('\r\n');
  const lines = [
    `From: NAEEES Elections <${process.env.GMAIL_USER}>`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    htmlBase64
  ];

  return Buffer.from(lines.join('\r\n'))
    .toString('base64url');
}

const sendOtp = async (to, subject, html) => {
  validateEmailConfiguration();

  try {
    const accessToken = await getAccessToken();
    const response = await axios.post(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
      { raw: buildRawEmail(to, subject, html) },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    return { success: true, service: 'Gmail API', data: response.data };
  } catch (error) {
    const status = error.response?.status;
    const details = error.response?.data?.error?.message || error.message;
    console.error('[Gmail API] Email request failed:', { status, details });
    throw new Error(`Gmail API request failed${status ? ` (${status})` : ''}: ${details}`);
  }
};

module.exports = { sendOtp };
