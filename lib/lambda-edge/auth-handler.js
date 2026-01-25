'use strict';

const https = require('https');
const crypto = require('crypto');

// Configuration - will be replaced at deploy time by CDK
const CONFIG = {
  userPoolId: '{{USER_POOL_ID}}',
  clientId: '{{CLIENT_ID}}',
  clientSecret: '{{CLIENT_SECRET}}',
  cognitoDomain: '{{COGNITO_DOMAIN}}',
  jwksUri: '{{JWKS_URI}}',
  issuer: '{{ISSUER}}',
  callbackPath: '/_callback',
  logoutPath: '/_logout',
  region: '{{REGION}}',
  cookieDomain: '{{COOKIE_DOMAIN}}',
};

// JWKS cache (in-memory, persists across warm invocations)
let jwksCache = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 3600000; // 1 hour

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}

function base64UrlToBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// Fetch JWKS from Cognito
async function fetchJwks() {
  const now = Date.now();
  if (jwksCache && (now - jwksCacheTime) < JWKS_CACHE_TTL) {
    return jwksCache;
  }

  return new Promise((resolve, reject) => {
    https.get(CONFIG.jwksUri, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          jwksCache = JSON.parse(data);
          jwksCacheTime = now;
          resolve(jwksCache);
        } catch (e) {
          reject(new Error('Failed to parse JWKS: ' + e.message));
        }
      });
    }).on('error', reject);
  });
}

// Find the correct key from JWKS
function findKey(jwks, kid) {
  return jwks.keys.find(key => key.kid === kid);
}

// Convert JWK to PEM format for verification
function jwkToPem(jwk) {
  if (jwk.kty !== 'RSA') {
    throw new Error('Unsupported key type: ' + jwk.kty);
  }

  const n = base64UrlToBuffer(jwk.n);
  const e = base64UrlToBuffer(jwk.e);

  // ASN.1 DER length encoding helper
  function encodeLength(len) {
    if (len < 128) {
      return Buffer.from([len]);
    } else if (len < 256) {
      return Buffer.from([0x81, len]);
    } else {
      return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    }
  }

  // Integer encoding helper
  function encodeInteger(buf) {
    // Add leading zero if high bit is set (to indicate positive number)
    if (buf[0] & 0x80) {
      buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
    return Buffer.concat([Buffer.from([0x02]), encodeLength(buf.length), buf]);
  }

  // Sequence encoding helper
  function encodeSequence(content) {
    return Buffer.concat([Buffer.from([0x30]), encodeLength(content.length), content]);
  }

  // BitString encoding helper (with proper length handling)
  function encodeBitString(content) {
    const len = content.length + 1; // +1 for unused bits byte
    return Buffer.concat([Buffer.from([0x03]), encodeLength(len), Buffer.from([0x00]), content]);
  }

  const nEncoded = encodeInteger(n);
  const eEncoded = encodeInteger(e);
  const rsaPublicKey = encodeSequence(Buffer.concat([nEncoded, eEncoded]));

  // RSA OID: 1.2.840.113549.1.1.1
  const rsaOid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const algorithmIdentifier = encodeSequence(rsaOid);

  // Wrap public key in BitString with proper length encoding
  const bitString = encodeBitString(rsaPublicKey);

  const publicKeyInfo = encodeSequence(Buffer.concat([algorithmIdentifier, bitString]));

  // Convert to PEM
  const base64 = publicKeyInfo.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----';
}

// Verify JWT signature using JWKS
async function verifyTokenSignature(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.error('Invalid token format');
      return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(base64UrlDecode(headerB64));
    const payload = JSON.parse(base64UrlDecode(payloadB64));

    // Verify algorithm
    if (header.alg !== 'RS256') {
      console.error('Unsupported algorithm:', header.alg);
      return null;
    }

    // Fetch JWKS and find the key
    const jwks = await fetchJwks();
    const key = findKey(jwks, header.kid);
    if (!key) {
      console.error('Key not found in JWKS:', header.kid);
      return null;
    }

    // Convert JWK to PEM
    const pem = jwkToPem(key);

    // Verify signature
    const signatureInput = headerB64 + '.' + payloadB64;
    const signature = base64UrlToBuffer(signatureB64);

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signatureInput);

    if (!verifier.verify(pem, signature)) {
      console.error('Signature verification failed');
      return null;
    }

    // Verify issuer
    if (payload.iss !== CONFIG.issuer) {
      console.error('Invalid issuer:', payload.iss);
      return null;
    }

    // Verify expiration
    if (payload.exp && payload.exp < Date.now() / 1000) {
      console.error('Token expired');
      return null;
    }

    // Verify audience (for id_token) or client_id (for access_token)
    if (payload.aud !== CONFIG.clientId && payload.client_id !== CONFIG.clientId) {
      console.error('Invalid audience/client_id');
      return null;
    }

    // Verify token_use for id_token
    if (payload.token_use && payload.token_use !== 'id') {
      console.error('Invalid token_use:', payload.token_use);
      return null;
    }

    return payload;
  } catch (e) {
    console.error('Token verification error:', e);
    return null;
  }
}

/**
 * Get a single cookie value by name (returns first match)
 * @param {Array<{value: string}>|undefined} cookies - Cookie headers from CloudFront request
 * @param {string} name - Cookie name to find
 * @returns {string|null} Cookie value or null if not found
 */
function getCookie(cookies, name) {
  if (!cookies) return null;
  for (const cookie of cookies) {
    const match = cookie.value.match(new RegExp(`${name}=([^;]+)`));
    if (match) return match[1];
  }
  return null;
}

/**
 * Get ALL cookies with the given name (handles multiple cookies from different User Pools/domains)
 * This is essential when users have stale cookies from old User Pools or different deployments.
 * @param {Array<{value: string}>|undefined} cookies - Cookie headers from CloudFront request
 * @param {string} name - Cookie name to find
 * @returns {string[]} Array of all cookie values with the given name
 */
function getAllCookies(cookies, name) {
  if (!cookies) return [];
  const results = [];
  const regex = new RegExp(`${name}=([^;]+)`, 'g');
  for (const cookie of cookies) {
    let match;
    while ((match = regex.exec(cookie.value)) !== null) {
      results.push(match[1]);
    }
    regex.lastIndex = 0; // Reset regex state for next cookie header
  }
  return results;
}

function parseQueryString(qs) {
  if (!qs) return {};
  return qs.split('&').reduce((acc, pair) => {
    const [key, value] = pair.split('=');
    acc[decodeURIComponent(key)] = decodeURIComponent(value || '');
    return acc;
  }, {});
}

function buildLoginUrl(request) {
  const host = request.headers.host[0].value;
  const uri = request.uri;
  const querystring = request.querystring || '';
  const state = Buffer.from(JSON.stringify({ uri, querystring })).toString('base64url');

  return `https://${CONFIG.cognitoDomain}/login?response_type=code&client_id=${CONFIG.clientId}&redirect_uri=https://${host}${CONFIG.callbackPath}&state=${state}&scope=openid+email+profile`;
}

async function exchangeCodeForTokens(code, redirectUri) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(`${CONFIG.clientId}:${CONFIG.clientSecret}`).toString('base64');
    const postData = `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}&client_id=${CONFIG.clientId}`;

    const options = {
      hostname: CONFIG.cognitoDomain,
      port: 443,
      path: '/oauth2/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${auth}`,
        'Content-Length': Buffer.byteLength(postData),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse token response: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

// Runtime subdomain parsing - {port}-{cid}.runtime.{subdomain}.{domain}
function parseRuntimeSubdomain(host) {
  // Match: {port}-{convId}.runtime.openhands.example.com
  const match = host.match(/^(\d+)-([a-f0-9]{32})\.runtime\./);
  if (match) {
    return { port: match[1], convId: match[2], isRuntime: true };
  }
  return { isRuntime: false };
}

/**
 * Try to verify multiple tokens and return the first valid one
 * @param {string[]} tokens - Array of JWT tokens to try
 * @returns {Promise<{payload: object, index: number}|null>} Valid payload and index, or null
 */
async function tryVerifyTokens(tokens) {
  for (let i = 0; i < tokens.length; i++) {
    try {
      const payload = await verifyTokenSignature(tokens[i]);
      if (payload) {
        return { payload, index: i };
      }
    } catch (e) {
      console.log(`Token ${i + 1}/${tokens.length} verification failed:`, e.message);
    }
  }
  return null;
}

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const uri = request.uri;
  const cookies = request.headers.cookie;
  const host = request.headers.host[0].value;

  // Check if this is a runtime subdomain request
  const runtime = parseRuntimeSubdomain(host);
  if (runtime.isRuntime) {
    // Runtime requests require authentication - verify JWT and inject user header
    // Note: We return 401 instead of redirecting to login because runtime subdomains
    // are not registered as valid Cognito callback URLs
    // Try all id_token cookies (handles multiple cookies from different User Pools)
    const idTokens = getAllCookies(cookies, 'id_token');
    if (idTokens.length === 0) {
      console.log('Runtime request without id_token, returning 401');
      return {
        status: '401',
        statusDescription: 'Unauthorized',
        headers: {
          'content-type': [{ key: 'Content-Type', value: 'text/plain' }],
        },
        body: 'Authentication required. Please login at the main application first.',
      };
    }

    const result = await tryVerifyTokens(idTokens);
    if (!result) {
      console.log('Runtime request with invalid token (tried ' + idTokens.length + ' tokens), returning 401');
      return {
        status: '401',
        statusDescription: 'Unauthorized',
        headers: {
          'content-type': [{ key: 'Content-Type', value: 'text/plain' }],
        },
        body: 'Invalid or expired token. Please login at the main application.',
      };
    }

    // Token is valid - inject user_id header for OpenResty to verify ownership
    delete request.headers['x-cognito-user-id'];
    request.headers['x-cognito-user-id'] = [{
      key: 'X-Cognito-User-Id',
      value: result.payload.sub
    }];
    console.log('Runtime request: verified user ' + result.payload.sub);

    // Rewrite URI to /runtime/{cid}/{port}/... format for ALB routing
    request.uri = '/runtime/' + runtime.convId + '/' + runtime.port + uri;
    return request;
  }

  // Handle callback from Cognito
  if (uri === CONFIG.callbackPath) {
    try {
      const params = parseQueryString(request.querystring);
      const code = params.code;
      const state = params.state;

      if (!code) {
        console.error('No code in callback');
        return {
          status: '400',
          statusDescription: 'Bad Request',
          body: 'Missing authorization code',
        };
      }

      // Exchange code for tokens
      const redirectUri = `https://${host}${CONFIG.callbackPath}`;
      const tokens = await exchangeCodeForTokens(code, redirectUri);

      if (!tokens.id_token) {
        console.error('No id_token in response:', tokens);
        return {
          status: '500',
          statusDescription: 'Internal Server Error',
          body: 'Failed to get tokens',
        };
      }

      // Verify the id_token signature before setting cookie
      const payload = await verifyTokenSignature(tokens.id_token);
      if (!payload) {
        console.error('Token verification failed after exchange');
        return {
          status: '500',
          statusDescription: 'Internal Server Error',
          body: 'Token verification failed',
        };
      }

      // Decode state to get original destination
      let destination = '/';
      if (state) {
        try {
          const stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
          destination = stateData.uri || '/';
          if (stateData.querystring) {
            destination += '?' + stateData.querystring;
          }
        } catch (e) {
          console.error('Failed to parse state:', e);
        }
      }

      // Calculate cookie expiry (1 day - matches id_token validity)
      const expiry = new Date(Date.now() + 86400000).toUTCString();

      return {
        status: '302',
        statusDescription: 'Found',
        headers: {
          location: [{ key: 'Location', value: destination }],
          'set-cookie': [
            { key: 'Set-Cookie', value: `id_token=${tokens.id_token}; Domain=${CONFIG.cookieDomain}; Path=/; Expires=${expiry}; HttpOnly; Secure; SameSite=Lax` },
          ],
        },
      };
    } catch (e) {
      console.error('Callback error:', e);
      return {
        status: '500',
        statusDescription: 'Internal Server Error',
        body: 'Authentication failed: ' + e.message,
      };
    }
  }

  // Handle logout
  if (uri === CONFIG.logoutPath) {
    const logoutUrl = `https://${CONFIG.cognitoDomain}/logout?client_id=${CONFIG.clientId}&logout_uri=https://${host}/`;
    return {
      status: '302',
      statusDescription: 'Found',
      headers: {
        location: [{ key: 'Location', value: logoutUrl }],
        'set-cookie': [{ key: 'Set-Cookie', value: `id_token=; Domain=${CONFIG.cookieDomain}; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure` }],
      },
    };
  }

  // Check for valid token with full JWKS signature verification
  // Try all id_token cookies (handles multiple cookies from different User Pools/domains)
  const idTokens = getAllCookies(cookies, 'id_token');
  const result = await tryVerifyTokens(idTokens);
  if (result) {
    // Token is valid (signature verified)
    // Clear any existing x-cognito-* headers to prevent spoofing
    delete request.headers['x-cognito-user-id'];
    delete request.headers['x-cognito-email'];
    delete request.headers['x-cognito-email-verified'];

    // Inject verified user information as headers for downstream services
    request.headers['x-cognito-user-id'] = [{
      key: 'X-Cognito-User-Id',
      value: result.payload.sub
    }];
    request.headers['x-cognito-email'] = [{
      key: 'X-Cognito-Email',
      value: result.payload.email || ''
    }];
    request.headers['x-cognito-email-verified'] = [{
      key: 'X-Cognito-Email-Verified',
      value: String(result.payload.email_verified || false)
    }];

    console.log('Authenticated user ' + result.payload.sub + ' (tried ' + (result.index + 1) + '/' + idTokens.length + ' tokens)');
    return request;
  }

  if (idTokens.length > 0) {
    console.log('All ' + idTokens.length + ' id_token cookies failed verification, redirecting to login');
  }

  // No valid token, redirect to login
  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: buildLoginUrl(request) }],
    },
  };
};

// Export functions for testing
module.exports = {
  handler: exports.handler,
  getCookie,
  getAllCookies,
  parseQueryString,
  parseRuntimeSubdomain,
  tryVerifyTokens,
  base64UrlDecode,
  base64UrlToBuffer,
  jwkToPem,
  findKey,
  // For testing: allow setting config
  _setConfig: (newConfig) => Object.assign(CONFIG, newConfig),
  _getConfig: () => CONFIG,
};
