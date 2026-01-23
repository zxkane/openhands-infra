/**
 * Unit tests for Lambda@Edge authentication handler
 *
 * This file tests the external Lambda@Edge handler at:
 *   lib/lambda-edge/auth-handler.js
 *
 * The handler is loaded from an external file (rather than inline in edge-stack.ts)
 * to enable unit testing. At CDK synth time, edge-stack.ts reads this file,
 * replaces config placeholders with actual values, and strips the module.exports.
 *
 * Key functionality tested:
 * - Cookie parsing for handling multiple id_token cookies from different User Pools
 *   (e.g., after User Pool recreation when users have stale cookies)
 * - Query string parsing for OAuth callback handling
 * - Runtime subdomain parsing for user app routing
 * - JWT utility functions (base64url decoding, JWK to PEM conversion)
 */

import * as path from 'path';
import * as fs from 'fs';

// Verify the auth handler file exists at the expected location
const AUTH_HANDLER_PATH = path.join(__dirname, '../lib/lambda-edge/auth-handler.js');

// Import the auth handler module from the external file
// eslint-disable-next-line @typescript-eslint/no-require-imports
const authHandler = require('../lib/lambda-edge/auth-handler');

describe('Lambda@Edge Auth Handler (lib/lambda-edge/auth-handler.js)', () => {
  // Verify the file exists before running tests
  beforeAll(() => {
    expect(fs.existsSync(AUTH_HANDLER_PATH)).toBe(true);
  });

  describe('getCookie (single cookie extraction)', () => {
    test('returns null for undefined cookies', () => {
      expect(authHandler.getCookie(undefined, 'id_token')).toBeNull();
    });

    test('returns null for empty cookies array', () => {
      expect(authHandler.getCookie([], 'id_token')).toBeNull();
    });

    test('extracts single cookie value', () => {
      const cookies = [{ value: 'id_token=abc123; other=value' }];
      expect(authHandler.getCookie(cookies, 'id_token')).toBe('abc123');
    });

    test('returns first match when multiple cookies exist', () => {
      const cookies = [
        { value: 'id_token=first_token; session=xyz' },
        { value: 'id_token=second_token; session=abc' },
      ];
      expect(authHandler.getCookie(cookies, 'id_token')).toBe('first_token');
    });

    test('returns null when cookie not found', () => {
      const cookies = [{ value: 'other_cookie=value; session=xyz' }];
      expect(authHandler.getCookie(cookies, 'id_token')).toBeNull();
    });

    test('handles cookie with no value after name', () => {
      const cookies = [{ value: 'id_token=; other=value' }];
      // Empty value should not match the pattern [^;]+
      expect(authHandler.getCookie(cookies, 'id_token')).toBeNull();
    });
  });

  describe('getAllCookies (multiple cookie extraction)', () => {
    test('returns empty array for undefined cookies', () => {
      expect(authHandler.getAllCookies(undefined, 'id_token')).toEqual([]);
    });

    test('returns empty array for empty cookies array', () => {
      expect(authHandler.getAllCookies([], 'id_token')).toEqual([]);
    });

    test('extracts single cookie value', () => {
      const cookies = [{ value: 'id_token=abc123; other=value' }];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual(['abc123']);
    });

    test('extracts multiple cookies from separate headers', () => {
      const cookies = [
        { value: 'id_token=token_from_user_pool_1; session=xyz' },
        { value: 'id_token=token_from_user_pool_2; session=abc' },
      ];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual([
        'token_from_user_pool_1',
        'token_from_user_pool_2',
      ]);
    });

    test('extracts multiple cookies from single header (edge case)', () => {
      // Some proxies may combine cookies with semicolons
      const cookies = [
        { value: 'id_token=token1; id_token=token2; session=xyz' },
      ];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual(['token1', 'token2']);
    });

    test('handles mixed cookie headers', () => {
      const cookies = [
        { value: 'id_token=old_user_pool_token; session=old' },
        { value: 'other_cookie=value' },
        { value: 'id_token=new_user_pool_token; session=new' },
      ];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual([
        'old_user_pool_token',
        'new_user_pool_token',
      ]);
    });

    test('returns empty array when cookie not found', () => {
      const cookies = [{ value: 'other_cookie=value; session=xyz' }];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual([]);
    });

    test('handles JWT tokens with special characters', () => {
      // JWT tokens contain base64url characters (-, _)
      const jwtToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-with_special';
      const cookies = [{ value: `id_token=${jwtToken}; session=xyz` }];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual([jwtToken]);
    });

    test('handles cookies from different domains (real-world scenario)', () => {
      // Simulates the bug: user has cookies from old and new User Pools
      const oldPoolToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Im9sZC1rZXkifQ.old-payload.old-sig';
      const newPoolToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Im5ldy1rZXkifQ.new-payload.new-sig';

      const cookies = [
        { value: `id_token=${oldPoolToken}; Path=/; Domain=.example.com` },
        { value: `id_token=${newPoolToken}; Path=/; Domain=.example.com` },
      ];

      const tokens = authHandler.getAllCookies(cookies, 'id_token');
      expect(tokens).toHaveLength(2);
      expect(tokens).toContain(oldPoolToken);
      expect(tokens).toContain(newPoolToken);
    });

    test('correctly resets regex between cookie headers', () => {
      // Ensure regex state doesn't leak between iterations
      const cookies = [
        { value: 'id_token=first' },
        { value: 'id_token=second' },
        { value: 'id_token=third' },
      ];
      expect(authHandler.getAllCookies(cookies, 'id_token')).toEqual([
        'first',
        'second',
        'third',
      ]);
    });

    test('tokens are returned in the order they appear', () => {
      const cookies = [
        { value: 'id_token=should_be_first' },
        { value: 'id_token=should_be_second' },
        { value: 'id_token=should_be_third' },
      ];

      const tokens = authHandler.getAllCookies(cookies, 'id_token');
      expect(tokens[0]).toBe('should_be_first');
      expect(tokens[1]).toBe('should_be_second');
      expect(tokens[2]).toBe('should_be_third');
    });
  });

  describe('parseQueryString', () => {
    test('returns empty object for undefined input', () => {
      expect(authHandler.parseQueryString(undefined)).toEqual({});
    });

    test('returns empty object for empty string', () => {
      expect(authHandler.parseQueryString('')).toEqual({});
    });

    test('parses single parameter', () => {
      expect(authHandler.parseQueryString('code=abc123')).toEqual({ code: 'abc123' });
    });

    test('parses multiple parameters', () => {
      expect(authHandler.parseQueryString('code=abc123&state=xyz789')).toEqual({
        code: 'abc123',
        state: 'xyz789',
      });
    });

    test('handles URL-encoded values', () => {
      expect(authHandler.parseQueryString('redirect_uri=https%3A%2F%2Fexample.com')).toEqual({
        redirect_uri: 'https://example.com',
      });
    });

    test('handles empty values', () => {
      expect(authHandler.parseQueryString('key=')).toEqual({ key: '' });
    });
  });

  describe('parseRuntimeSubdomain', () => {
    test('parses valid runtime subdomain', () => {
      // Conv ID must be exactly 32 hex characters
      const result = authHandler.parseRuntimeSubdomain('5000-abc123def456789012345678901234ab.runtime.openhands.example.com');
      expect(result).toEqual({
        port: '5000',
        convId: 'abc123def456789012345678901234ab',
        isRuntime: true,
      });
    });

    test('returns isRuntime false for non-runtime host', () => {
      const result = authHandler.parseRuntimeSubdomain('openhands.example.com');
      expect(result).toEqual({ isRuntime: false });
    });

    test('returns isRuntime false for invalid port format', () => {
      const result = authHandler.parseRuntimeSubdomain('abc-abc123def456789012345678901234ab.runtime.openhands.example.com');
      expect(result).toEqual({ isRuntime: false });
    });

    test('returns isRuntime false for invalid conversation ID length', () => {
      const result = authHandler.parseRuntimeSubdomain('5000-short.runtime.openhands.example.com');
      expect(result).toEqual({ isRuntime: false });
    });

    test('parses different port numbers', () => {
      // Conv ID must be exactly 32 hex characters
      const result = authHandler.parseRuntimeSubdomain('3000-abc123def456789012345678901234ab.runtime.test.example.com');
      expect(result.port).toBe('3000');
      expect(result.isRuntime).toBe(true);
    });
  });

  describe('base64UrlDecode', () => {
    test('decodes standard base64url string', () => {
      // "hello" in base64url
      const encoded = 'aGVsbG8';
      expect(authHandler.base64UrlDecode(encoded)).toBe('hello');
    });

    test('handles base64url with - and _ characters', () => {
      // These characters are different from standard base64 (+ and /)
      const encoded = 'SGVsbG8td29ybGRf'; // "Hello-world_" approximately
      const decoded = authHandler.base64UrlDecode(encoded);
      expect(decoded).toBeDefined();
    });

    test('handles missing padding', () => {
      // base64url often omits padding
      const encoded = 'dGVzdA'; // "test" without padding
      expect(authHandler.base64UrlDecode(encoded)).toBe('test');
    });
  });

  describe('base64UrlToBuffer', () => {
    test('converts base64url to buffer', () => {
      const encoded = 'aGVsbG8'; // "hello"
      const buffer = authHandler.base64UrlToBuffer(encoded);
      expect(Buffer.isBuffer(buffer)).toBe(true);
      expect(buffer.toString()).toBe('hello');
    });

    test('handles base64url special characters', () => {
      // Test with - and _ which are base64url specific
      const encoded = 'YWJjLWRlZl9naGk'; // Contains special chars when decoded
      const buffer = authHandler.base64UrlToBuffer(encoded);
      expect(Buffer.isBuffer(buffer)).toBe(true);
    });
  });

  describe('findKey', () => {
    test('finds key by kid', () => {
      const jwks = {
        keys: [
          { kid: 'key1', kty: 'RSA', n: 'abc', e: 'AQAB' },
          { kid: 'key2', kty: 'RSA', n: 'def', e: 'AQAB' },
        ],
      };
      const key = authHandler.findKey(jwks, 'key2');
      expect(key).toEqual({ kid: 'key2', kty: 'RSA', n: 'def', e: 'AQAB' });
    });

    test('returns undefined for non-existent kid', () => {
      const jwks = {
        keys: [{ kid: 'key1', kty: 'RSA', n: 'abc', e: 'AQAB' }],
      };
      const key = authHandler.findKey(jwks, 'nonexistent');
      expect(key).toBeUndefined();
    });

    test('handles empty keys array', () => {
      const jwks = { keys: [] };
      const key = authHandler.findKey(jwks, 'any');
      expect(key).toBeUndefined();
    });
  });

  describe('jwkToPem', () => {
    test('converts RSA JWK to PEM format', () => {
      // Minimal valid RSA JWK (small key for testing)
      const jwk = {
        kty: 'RSA',
        n: 'sXchDaQebSXKcvLsYX3DCqpLkoLJgt7XkPA3e1P15x8gVFnHkYSCYcJKagxKPzPR5Pq0iK2s1CFcRbACYPnZvL_xKYa3g7Lw',
        e: 'AQAB',
      };
      const pem = authHandler.jwkToPem(jwk);
      expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
      expect(pem).toContain('-----END PUBLIC KEY-----');
    });

    test('throws error for non-RSA key type', () => {
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: 'abc',
        y: 'def',
      };
      expect(() => authHandler.jwkToPem(jwk)).toThrow('Unsupported key type: EC');
    });
  });

  describe('Configuration', () => {
    test('can get and set config', () => {
      const originalConfig = authHandler._getConfig();
      expect(originalConfig.callbackPath).toBe('/_callback');
      expect(originalConfig.logoutPath).toBe('/_logout');

      authHandler._setConfig({ clientId: 'test-client-id' });
      expect(authHandler._getConfig().clientId).toBe('test-client-id');

      // Reset for other tests
      authHandler._setConfig({ clientId: '{{CLIENT_ID}}' });
    });
  });
});
