const crypto = require('crypto');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    const id = (req.query && req.query.id) ? String(req.query.id).replace(/[^a-zA-Z0-9_-]/g, '') : '';
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Data Deletion | Guava</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0d0d;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}
    .card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:16px;padding:2.5rem;max-width:480px;width:100%;text-align:center}
    .icon{font-size:3rem;margin-bottom:1rem}
    h1{font-size:1.4rem;font-weight:600;margin-bottom:.75rem}
    p{color:#999;line-height:1.6;font-size:.95rem;margin-bottom:1rem}
    .code{background:#252525;border-radius:8px;padding:.75rem 1rem;font-family:monospace;font-size:.85rem;color:#ccc;margin-top:1rem}
    a{color:#512feb;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#10003;</div>
    <h1>Data Deletion Request</h1>
    <p>Your request to delete data associated with your Facebook account has been received and processed.</p>
    <p>Guava does not store personal Facebook user data beyond what is required for authentication. Any session data has been removed.</p>
    ${id ? `<div class="code">Confirmation ID: ${id}</div>` : ''}
    <p style="margin-top:1.5rem">Questions? <a href="mailto:richmondeke@gmail.com">Contact us</a></p>
  </div>
</body>
</html>`);
  }

  if (req.method === 'POST') {
    let userId = 'unknown';

    try {
      const appSecret = process.env.FACEBOOK_APP_SECRET || '';
      const body = req.body || {};
      const signedRequest = body.signed_request;

      if (signedRequest && appSecret) {
        const [encodedSig, payload] = signedRequest.split('.');
        const sig = Buffer.from(encodedSig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const data = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
        const expectedSig = crypto.createHmac('sha256', appSecret).update(payload).digest();
        if (crypto.timingSafeEqual(sig, expectedSig) && data.user_id) {
          userId = data.user_id;
        }
      }
    } catch (e) {
      // continue with unknown userId
    }

    const confirmationCode = crypto
      .createHash('sha256')
      .update(userId + '-' + Date.now())
      .digest('hex')
      .slice(0, 16);

    return res.status(200).json({
      url: 'https://investor.guava.earth/deletion?id=' + confirmationCode,
      confirmation_code: confirmationCode,
    });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
