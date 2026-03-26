const https = require('https');

const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Simple HMAC-SHA256 verification without external libraries
const crypto = require('crypto');

function verifyStripeSignature(payload, sigHeader, secret) {
  try {
    const parts = sigHeader.split(',');
    const timestamp = parts.find(p => p.startsWith('t=')).split('=')[1];
    const signature = parts.find(p => p.startsWith('v1=')).split('=')[1];
    const signedPayload = timestamp + '.' + payload;
    const expectedSig = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
    const tolerance = 300; // 5 minutes
    if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > tolerance) return false;
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig));
  } catch (e) {
    return false;
  }
}

function stripeRequest(path, method, data) {
  return new Promise((resolve, reject) => {
    const postData = data ? JSON.stringify(data) : null;
    const options = {
      hostname: 'api.stripe.com',
      path: path,
      method: method || 'GET',
      headers: {
        'Authorization': 'Bearer ' + STRIPE_SECRET,
        'Content-Type': 'application/json',
        'Stripe-Version': '2023-10-16'
      }
    };
    if (postData) options.headers['Content-Length'] = Buffer.byteLength(postData);
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Handle Stripe webhook
  if (event.httpMethod === 'POST' && event.headers['stripe-signature']) {
    const sig = event.headers['stripe-signature'];
    const valid = verifyStripeSignature(event.body, sig, WEBHOOK_SECRET);
    if (!valid) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid signature' }) };
    }
    const stripeEvent = JSON.parse(event.body);
    if (stripeEvent.type === 'checkout.session.completed') {
      const session = stripeEvent.data.object;
      const token = crypto.randomBytes(32).toString('hex');
      const expiry = Date.now() + (2 * 60 * 60 * 1000); // 2 hours
      // Store token in Stripe metadata on the payment intent
      if (session.payment_intent) {
        await stripeRequest('/v1/payment_intents/' + session.payment_intent, 'POST',
          'metadata[access_token]=' + token + '&metadata[token_expiry]=' + expiry
        ).catch(() => {});
      }
      return { statusCode: 200, headers, body: JSON.stringify({ received: true }) };
    }
    return { statusCode: 200, headers, body: JSON.stringify({ received: true }) };
  }

  // Handle token verification from frontend
  if (event.httpMethod === 'GET') {
    const token = event.queryStringParameters && event.queryStringParameters.token;
    const sessionId = event.queryStringParameters && event.queryStringParameters.session_id;

    if (!token || !sessionId) {
      return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Missing parameters' }) };
    }

    try {
      // Retrieve checkout session from Stripe
      const session = await stripeRequest('/v1/checkout/sessions/' + sessionId + '?expand[]=payment_intent', 'GET');
      if (!session || session.error) {
        return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Session not found' }) };
      }
      if (session.payment_status !== 'paid') {
        return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Payment not completed' }) };
      }
      const pi = session.payment_intent;
      const storedToken = pi && pi.metadata && pi.metadata.access_token;
      const expiry = pi && pi.metadata && pi.metadata.token_expiry;

      if (!storedToken || storedToken !== token) {
        return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Invalid token' }) };
      }
      if (expiry && Date.now() > parseInt(expiry)) {
        return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Token expired' }) };
      }
      // Invalidate token after use
      if (pi && pi.id) {
        await stripeRequest('/v1/payment_intents/' + pi.id, 'POST',
          'metadata[access_token]=used&metadata[token_used_at]=' + Date.now()
        ).catch(() => {});
      }
      return { statusCode: 200, headers, body: JSON.stringify({ valid: true }) };
    } catch (err) {
      return { statusCode: 500, headers, body: JSON.stringify({ valid: false, error: err.message }) };
    }
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
};
