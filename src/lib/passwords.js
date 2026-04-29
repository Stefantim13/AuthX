const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

const HASH_CONFIG = {
  keyLength: 64,
  saltLength: 16,
  minLength: 10,
  tokenBytes: 32,
  resetTokenMinutes: 15,
  maxFailedAttempts: 5,
  lockMinutes: 15
};

const PASSWORD_POLICY_MESSAGE =
  'Password must be at least 10 characters long and include uppercase, lowercase, number, and special character.';

function validatePasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < HASH_CONFIG.minLength) {
    return PASSWORD_POLICY_MESSAGE;
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
    return PASSWORD_POLICY_MESSAGE;
  }

  return null;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(HASH_CONFIG.saltLength).toString('hex');
  const derivedKey = await scryptAsync(password, salt, HASH_CONFIG.keyLength);
  return `scrypt$${salt}$${Buffer.from(derivedKey).toString('hex')}`;
}

function hashPasswordSync(password) {
  const salt = crypto.randomBytes(HASH_CONFIG.saltLength).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, HASH_CONFIG.keyLength);
  return `scrypt$${salt}$${Buffer.from(derivedKey).toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string') {
    return false;
  }

  const [algorithm, salt, hashHex] = storedHash.split('$');
  if (algorithm !== 'scrypt' || !salt || !hashHex) {
    return false;
  }

  const expectedHash = Buffer.from(hashHex, 'hex');
  const derivedKey = await scryptAsync(password, salt, expectedHash.length);
  const actualHash = Buffer.from(derivedKey);

  if (expectedHash.length !== actualHash.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedHash, actualHash);
}

const DUMMY_HASH = hashPasswordSync('DummyPassword!234');

function generateResetToken() {
  return crypto.randomBytes(HASH_CONFIG.tokenBytes).toString('hex');
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  DUMMY_HASH,
  HASH_CONFIG,
  PASSWORD_POLICY_MESSAGE,
  generateResetToken,
  hashPassword,
  hashPasswordSync,
  hashResetToken,
  validatePasswordPolicy,
  verifyPassword
};
