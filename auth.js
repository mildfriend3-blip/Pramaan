// auth.js - Secure Authentication, Session Management & RBAC
const crypto = require('node:crypto');

const ITERATIONS = 100000;
const KEY_LEN = 64;
const DIGEST = 'sha512';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// In-memory rate limiting map for brute force prevention
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(32).toString('hex');
  }
  const derivedKey = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, DIGEST);
  return {
    hash: derivedKey.toString('hex'),
    salt
  };
}

function verifyPassword(password, storedHash, salt) {
  try {
    const derivedKey = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, DIGEST);
    const hashBuffer = Buffer.from(storedHash, 'hex');
    const derivedBuffer = derivedKey;
    if (hashBuffer.length !== derivedBuffer.length) {
      return false;
    }
    return crypto.timingSafeEqual(hashBuffer, derivedBuffer);
  } catch {
    return false;
  }
}

function checkRateLimit(identifier) {
  const now = Date.now();
  const record = loginAttempts.get(identifier);

  if (!record) {
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }

  if (now - record.firstAttempt > LOCKOUT_WINDOW_MS) {
    loginAttempts.delete(identifier);
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }

  if (record.count >= MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((LOCKOUT_WINDOW_MS - (now - record.firstAttempt)) / 1000);
    return { allowed: false, retryAfter };
  }

  return { allowed: true, remaining: MAX_ATTEMPTS - record.count };
}

function recordLoginAttempt(identifier, success) {
  if (success) {
    loginAttempts.delete(identifier);
    return;
  }

  const now = Date.now();
  const record = loginAttempts.get(identifier);
  if (!record || now - record.firstAttempt > LOCKOUT_WINDOW_MS) {
    loginAttempts.set(identifier, { count: 1, firstAttempt: now });
  } else {
    record.count += 1;
  }
}

function generateSessionToken() {
  return 'prm_' + crypto.randomBytes(32).toString('hex');
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  const items = cookieHeader.split(';');
  for (const item of items) {
    const parts = item.split('=');
    if (parts.length >= 2) {
      const key = parts[0].trim();
      const val = parts.slice(1).join('=').trim();
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

module.exports = {
  hashPassword,
  verifyPassword,
  checkRateLimit,
  recordLoginAttempt,
  generateSessionToken,
  parseCookies,
  SESSION_TTL_MS
};
