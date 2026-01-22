import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { OpenHandsConfig, ComputeStackOutput } from './interfaces.js';

export interface EdgeStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  computeOutput: ComputeStackOutput;
  alb: elbv2.IApplicationLoadBalancer;
}

/**
 * EdgeStack - Combined Auth and CDN infrastructure (us-east-1)
 *
 * This stack must be deployed to us-east-1 for Lambda@Edge and CloudFront certificates.
 *
 * Components:
 * - Cognito User Pool for user authentication
 * - Lambda@Edge function for JWT validation
 * - ACM certificate for CloudFront
 * - CloudFront distribution with VPC Origin
 * - WAF WebACL with managed rules
 * - Route 53 alias record
 */
export class EdgeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: EdgeStackProps) {
    super(scope, id, props);

    const { config, alb } = props;
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const runtimeDomain = `runtime.${fullDomain}`; // e.g., runtime.openhands.test.kane.mx

    // ========================================
    // Route 53 & Certificate
    // ========================================

    // Import existing Route 53 Hosted Zone
    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
      hostedZoneId: config.hostedZoneId,
      zoneName: config.domainName,
    });

    // ACM Certificate for CloudFront (must be in us-east-1)
    // Includes both main domain and runtime wildcard as SAN
    const certificate = new acm.Certificate(this, 'Certificate', {
      domainName: fullDomain,
      subjectAlternativeNames: [`*.${runtimeDomain}`], // *.runtime.openhands.test.kane.mx
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ========================================
    // Cognito User Pool
    // ========================================

    const userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false, // Admin creates users
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        email: {
          required: true,
          mutable: true,
        },
      },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Cognito Domain
    const userPoolDomain = userPool.addDomain('CognitoDomain', {
      cognitoDomain: {
        domainPrefix: `openhands-${cdk.Aws.ACCOUNT_ID}`,
      },
    });

    // Cognito App Client with 30-day session validity
    const userPoolClient = userPool.addClient('WebAppClient', {
      generateSecret: true,
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: [
          `https://${fullDomain}/_callback`,
        ],
        logoutUrls: [
          `https://${fullDomain}/`,
        ],
      },
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      preventUserExistenceErrors: true,
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
      ],
      // Token validity - 30 day session
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.days(1),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ========================================
    // Store Client Secret in Secrets Manager
    // ========================================

    // Store the Cognito client secret in Secrets Manager for secure access
    // Note: Lambda@Edge cannot access Secrets Manager at runtime, so we fetch at deploy time
    // The secret is still stored securely and can be rotated via Secrets Manager
    const clientSecret = new secretsmanager.Secret(this, 'CognitoClientSecret', {
      secretName: `openhands/cognito-client-secret`,
      description: 'Cognito User Pool Client Secret for OpenHands',
      secretStringValue: userPoolClient.userPoolClientSecret,
    });

    // Get the secret value for Lambda@Edge (retrieved at deploy time)
    // Lambda@Edge runs at edge locations and cannot access regional Secrets Manager
    // Using unsafeUnwrap() because Lambda@Edge cannot access Secrets Manager at runtime
    const clientSecretValue = userPoolClient.userPoolClientSecret.unsafeUnwrap();

    // ========================================
    // Lambda@Edge for Authentication
    // ========================================

    const authFunctionRole = new iam.Role(this, 'AuthFunctionRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Lambda@Edge function with proper JWKS signature verification
    const authFunction = new lambda.Function(this, 'AuthFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
const https = require('https');
const crypto = require('crypto');

// Configuration (embedded at deploy time - Lambda@Edge cannot access regional services)
const CONFIG = {
  userPoolId: '${userPool.userPoolId}',
  clientId: '${userPoolClient.userPoolClientId}',
  clientSecret: '${clientSecretValue}',
  cognitoDomain: '${userPoolDomain.domainName}.auth.${this.region}.amazoncognito.com',
  jwksUri: 'https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}/.well-known/jwks.json',
  issuer: 'https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}',
  callbackPath: '/_callback',
  logoutPath: '/_logout',
  region: '${this.region}',
  cookieDomain: '.${config.domainName}',  // Use base domain for cookie sharing across all subdomains including *.runtime.{fullDomain}
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
  return '-----BEGIN PUBLIC KEY-----\\n' + lines.join('\\n') + '\\n-----END PUBLIC KEY-----';
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

function getCookie(cookies, name) {
  if (!cookies) return null;
  for (const cookie of cookies) {
    const match = cookie.value.match(new RegExp(\`\${name}=([^;]+)\`));
    if (match) return match[1];
  }
  return null;
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

  return \`https://\${CONFIG.cognitoDomain}/login?response_type=code&client_id=\${CONFIG.clientId}&redirect_uri=https://\${host}\${CONFIG.callbackPath}&state=\${state}&scope=openid+email+profile\`;
}

async function exchangeCodeForTokens(code, redirectUri) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(\`\${CONFIG.clientId}:\${CONFIG.clientSecret}\`).toString('base64');
    const postData = \`grant_type=authorization_code&code=\${code}&redirect_uri=\${encodeURIComponent(redirectUri)}&client_id=\${CONFIG.clientId}\`;

    const options = {
      hostname: CONFIG.cognitoDomain,
      port: 443,
      path: '/oauth2/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': \`Basic \${auth}\`,
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
          reject(new Error(\`Failed to parse token response: \${data}\`));
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
  // Match: {port}-{convId}.runtime.openhands.test.kane.mx
  const match = host.match(/^(\\d+)-([a-f0-9]{32})\\.runtime\\./);
  if (match) {
    return { port: match[1], convId: match[2], isRuntime: true };
  }
  return { isRuntime: false };
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
    const idToken = getCookie(cookies, 'id_token');
    if (!idToken) {
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

    const payload = await verifyTokenSignature(idToken);
    if (!payload) {
      console.log('Runtime request with invalid token, returning 401');
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
      value: payload.sub
    }];

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
      const redirectUri = \`https://\${host}\${CONFIG.callbackPath}\`;
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
            { key: 'Set-Cookie', value: \`id_token=\${tokens.id_token}; Domain=\${CONFIG.cookieDomain}; Path=/; Expires=\${expiry}; HttpOnly; Secure; SameSite=Lax\` },
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
    const logoutUrl = \`https://\${CONFIG.cognitoDomain}/logout?client_id=\${CONFIG.clientId}&logout_uri=https://\${host}/\`;
    return {
      status: '302',
      statusDescription: 'Found',
      headers: {
        location: [{ key: 'Location', value: logoutUrl }],
        'set-cookie': [{ key: 'Set-Cookie', value: \`id_token=; Domain=\${CONFIG.cookieDomain}; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure\` }],
      },
    };
  }

  // Check for valid token with full JWKS signature verification
  const idToken = getCookie(cookies, 'id_token');
  if (idToken) {
    const payload = await verifyTokenSignature(idToken);
    if (payload) {
      // Token is valid (signature verified)
      // Clear any existing x-cognito-* headers to prevent spoofing
      delete request.headers['x-cognito-user-id'];
      delete request.headers['x-cognito-email'];
      delete request.headers['x-cognito-email-verified'];

      // Inject verified user information as headers for downstream services
      request.headers['x-cognito-user-id'] = [{
        key: 'X-Cognito-User-Id',
        value: payload.sub
      }];
      request.headers['x-cognito-email'] = [{
        key: 'X-Cognito-Email',
        value: payload.email || ''
      }];
      request.headers['x-cognito-email-verified'] = [{
        key: 'X-Cognito-Email-Verified',
        value: String(payload.email_verified || false)
      }];

      return request;
    }
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
`),
      role: authFunctionRole,
      timeout: cdk.Duration.seconds(5),
      memorySize: 128,
    });

    // Create version for Lambda@Edge
    const authFunctionVersion = authFunction.currentVersion;

    // ========================================
    // Lambda@Edge for Runtime Security Headers
    // ========================================

    const securityHeadersFunctionRole = new iam.Role(this, 'SecurityHeadersFunctionRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Lambda@Edge function for origin-response - adds security headers for runtime requests
    const securityHeadersFunction = new lambda.Function(this, 'SecurityHeadersFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
// Origin Response Handler - adds security headers for runtime requests
exports.handler = async (event) => {
  const response = event.Records[0].cf.response;
  const request = event.Records[0].cf.request;
  const host = request.headers.host ? request.headers.host[0].value : '';

  // Check if this is a runtime request (runtime subdomain)
  if (host.includes('.runtime.')) {
    const headers = response.headers;

    // Security headers - protect against cross-runtime attacks
    headers['x-frame-options'] = [{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }];
    headers['x-content-type-options'] = [{ key: 'X-Content-Type-Options', value: 'nosniff' }];
    headers['x-xss-protection'] = [{ key: 'X-XSS-Protection', value: '1; mode=block' }];
    headers['referrer-policy'] = [{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }];
    headers['content-security-policy'] = [{
      key: 'Content-Security-Policy',
      value: "frame-ancestors 'self'; default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:;"
    }];

    // Cookie security - rewrite Set-Cookie headers for isolation
    if (headers['set-cookie']) {
      headers['set-cookie'] = headers['set-cookie'].map(cookie => {
        let value = cookie.value;
        // Remove any Domain attribute (ensures cookie only valid for exact host)
        value = value.replace(/;\\s*Domain=[^;]*/gi, '');
        // Add Secure attribute if not present
        if (!/;\\s*Secure/i.test(value)) {
          value += '; Secure';
        }
        // Add SameSite=Strict if not present
        if (!/;\\s*SameSite/i.test(value)) {
          value += '; SameSite=Strict';
        }
        return { key: 'Set-Cookie', value };
      });
    }
  }

  return response;
};
`),
      role: securityHeadersFunctionRole,
      timeout: cdk.Duration.seconds(5),
      memorySize: 128,
    });

    // Create version for Lambda@Edge
    const securityHeadersFunctionVersion = securityHeadersFunction.currentVersion;

    // ========================================
    // WAF WebACL
    // ========================================

    const webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      defaultAction: { allow: {} },
      scope: 'CLOUDFRONT',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'OpenHandsWebAcl',
        sampledRequestsEnabled: true,
      },
      rules: [
        // AWS Managed Rules - Common Rule Set
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: 1,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              // Override SizeRestrictions_BODY rule to COUNT instead of BLOCK
              // OpenHands runtime API needs to send large payloads (50KB+) for conversation creation
              ruleActionOverrides: [
                {
                  name: 'SizeRestrictions_BODY',
                  actionToUse: { count: {} },
                },
              ],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesCommonRuleSet',
            sampledRequestsEnabled: true,
          },
        },
        // AWS Managed Rules - Known Bad Inputs
        {
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          priority: 2,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
            sampledRequestsEnabled: true,
          },
        },
        // Rate limiting rule - 50000 requests per 5 minutes per IP (increased for automated testing)
        {
          name: 'RateLimitRule',
          priority: 3,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 50000,
              aggregateKeyType: 'IP',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'RateLimitRule',
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    // ========================================
    // CloudFront Distribution with HTTP Origin
    // ========================================

    // Note: CloudFront VPC Origin does NOT support WebSocket connections.
    // We use internet-facing ALB with HttpOrigin to support WebSocket.
    const httpOrigin = new origins.HttpOrigin(alb.loadBalancerDnsName, {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
      readTimeout: cdk.Duration.seconds(60),
      keepaliveTimeout: cdk.Duration.seconds(60),
    });

    // Response Headers Policy for CORS support
    // Required because the origin sets access-control-allow-credentials but not access-control-allow-origin
    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'CorsHeadersPolicy', {
      responseHeadersPolicyName: `OpenHands-CORS-Headers-${this.account}`,
      comment: 'Adds CORS headers for credentialed requests',
      corsBehavior: {
        accessControlAllowCredentials: true,
        accessControlAllowOrigins: [`https://${fullDomain}`],
        accessControlAllowMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
        accessControlAllowHeaders: [
          'Accept',
          'Accept-Language',
          'Content-Language',
          'Content-Type',
          'Authorization',
          'Cache-Control',
          'Pragma',
          'Origin',
          'X-Requested-With',
        ],
        accessControlExposeHeaders: [
          'Content-Length',
          'Content-Type',
          'ETag',
          'Cache-Control',
        ],
        accessControlMaxAge: cdk.Duration.seconds(86400),
        originOverride: true,
      },
    });

    // CloudFront Distribution
    // Includes both main domain and runtime wildcard
    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'OpenHands CloudFront Distribution',
      domainNames: [
        fullDomain,                  // openhands.test.kane.mx (main app)
        `*.${runtimeDomain}`,        // *.runtime.openhands.test.kane.mx (runtime subdomains)
      ],
      certificate: certificate,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      webAclId: webAcl.attrArn,
      defaultBehavior: {
        origin: httpOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
        responseHeadersPolicy: responseHeadersPolicy,
        edgeLambdas: [
          {
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
            functionVersion: authFunctionVersion,
            includeBody: false,
          },
          {
            eventType: cloudfront.LambdaEdgeEventType.ORIGIN_RESPONSE,
            functionVersion: securityHeadersFunctionVersion,
            includeBody: false,
          },
        ],
      },
      // Runtime proxy behavior for path-based routing (/runtime/{conv_id}/{port}/...)
      // This is used for WebSocket connections to agent-server (sockets/events)
      // which require authentication via the main domain cookie
      additionalBehaviors: {
        '/runtime/*': {
          origin: httpOrigin,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
          responseHeadersPolicy: responseHeadersPolicy,
          // Add Lambda@Edge to verify JWT and inject X-Cognito-User-Id header
          // This is required for OpenResty to authorize runtime requests
          edgeLambdas: [
            {
              eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
              functionVersion: authFunctionVersion,
              includeBody: false,
            },
          ],
        },
      },
    });

    // ========================================
    // Route 53 DNS Records
    // ========================================

    // Main domain record: openhands.test.kane.mx
    new route53.ARecord(this, 'AliasRecord', {
      zone: hostedZone,
      recordName: config.subDomain,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(distribution)
      ),
    });

    // Runtime wildcard record: *.runtime.openhands.test.kane.mx
    new route53.ARecord(this, 'RuntimeWildcardRecord', {
      zone: hostedZone,
      recordName: `*.runtime.${config.subDomain}`,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(distribution)
      ),
    });

    // ========================================
    // CloudFormation Outputs
    // ========================================

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
    });

    new cdk.CfnOutput(this, 'CognitoDomainUrl', {
      value: `https://${userPoolDomain.domainName}.auth.${this.region}.amazoncognito.com`,
      description: 'Cognito Domain URL',
    });

    new cdk.CfnOutput(this, 'DistributionId', {
      value: distribution.distributionId,
      description: 'CloudFront Distribution ID',
    });

    new cdk.CfnOutput(this, 'DistributionDomainName', {
      value: distribution.distributionDomainName,
      description: 'CloudFront Distribution Domain Name',
    });

    new cdk.CfnOutput(this, 'CustomDomain', {
      value: `https://${fullDomain}`,
      description: 'Custom Domain URL',
    });

    new cdk.CfnOutput(this, 'WebAclArn', {
      value: webAcl.attrArn,
      description: 'WAF WebACL ARN',
    });

    new cdk.CfnOutput(this, 'ClientSecretArn', {
      value: clientSecret.secretArn,
      description: 'Cognito Client Secret ARN in Secrets Manager',
    });
  }
}
