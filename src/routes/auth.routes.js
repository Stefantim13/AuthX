const express = require('express');
const db = require('../db/connection');
const { getClientIp, writeAuditLog } = require('../lib/audit');
const {
  DUMMY_HASH,
  HASH_CONFIG,
  hashPassword,
  hashResetToken,
  generateResetToken,
  validatePasswordPolicy,
  verifyPassword
} = require('../lib/passwords');
const { isJsonRequest, respond } = require('../lib/respond');

const router = express.Router();

const INVALID_CREDENTIALS_MESSAGE = 'Invalid credentials';
const RESET_REQUEST_MESSAGE =
  'If the account exists, a reset token has been generated.';

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidRole(role) {
  return role === 'ANALYST' || role === 'MANAGER';
}

function renderLogin(res, options = {}) {
  return res.render('login', {
    error: null,
    success: null,
    ...options
  });
}

function renderRegister(res, options = {}) {
  return res.render('register', {
    error: null,
    success: null,
    ...options
  });
}

function renderForgotPassword(res, options = {}) {
  return res.render('forgot-password', {
    error: null,
    success: null,
    resetToken: null,
    ...options
  });
}

function renderResetPassword(res, options = {}) {
  return res.render('reset-password', {
    error: null,
    success: null,
    ...options
  });
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (isJsonRequest(req)) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    return res.redirect('/login');
  }

  return next();
}

function sanitizeLikeInput(value) {
  return String(value || '').trim().slice(0, 100);
}

function getTicketsForUser(user, searchTerm = '') {
  const normalizedSearch = sanitizeLikeInput(searchTerm);
  const searchPattern = `%${normalizedSearch}%`;

  if (user.role === 'MANAGER') {
    return db.prepare(`
      SELECT tickets.*, users.email AS owner_email
      FROM tickets
      JOIN users ON users.id = tickets.owner_id
      WHERE (? = '' OR tickets.title LIKE ? OR tickets.description LIKE ?)
      ORDER BY tickets.created_at DESC, tickets.id DESC
    `).all(normalizedSearch, searchPattern, searchPattern);
  }

  return db.prepare(`
    SELECT tickets.*, users.email AS owner_email
    FROM tickets
    JOIN users ON users.id = tickets.owner_id
    WHERE tickets.owner_id = ?
      AND (? = '' OR tickets.title LIKE ? OR tickets.description LIKE ?)
    ORDER BY tickets.created_at DESC, tickets.id DESC
  `).all(user.id, normalizedSearch, searchPattern, searchPattern);
}

function getTicketByIdForUser(ticketId, user) {
  if (user.role === 'MANAGER') {
    return db.prepare(`
      SELECT tickets.*, users.email AS owner_email
      FROM tickets
      JOIN users ON users.id = tickets.owner_id
      WHERE tickets.id = ?
    `).get(ticketId);
  }

  return db.prepare(`
    SELECT tickets.*, users.email AS owner_email
    FROM tickets
    JOIN users ON users.id = tickets.owner_id
    WHERE tickets.id = ? AND tickets.owner_id = ?
  `).get(ticketId, user.id);
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function destroySession(req) {
  return new Promise((resolve) => {
    req.session.destroy(() => resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

router.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }

  return renderLogin(res);
});

router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }

  return renderRegister(res);
});

router.get('/forgot-password', (req, res) => {
  return renderForgotPassword(res);
});

router.get('/reset-password', (req, res) => {
  return renderResetPassword(res);
});

router.post('/register', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const role = String(req.body.role || 'ANALYST');
    const ipAddress = getClientIp(req);

    if (!isValidEmail(email)) {
      return respond(
        req,
        res,
        400,
        { success: false, message: 'A valid email address is required' },
        'register',
        { error: 'A valid email address is required' }
      );
    }

    if (!isValidRole(role)) {
      return respond(
        req,
        res,
        400,
        { success: false, message: 'Invalid role selected' },
        'register',
        { error: 'Invalid role selected' }
      );
    }

    const passwordPolicyError = validatePasswordPolicy(password);
    if (passwordPolicyError) {
      return respond(
        req,
        res,
        400,
        { success: false, message: passwordPolicyError },
        'register',
        { error: passwordPolicyError }
      );
    }

    const existingUser = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(email);

    if (existingUser) {
      return respond(
        req,
        res,
        409,
        { success: false, message: 'An account already exists for this email' },
        'register',
        { error: 'An account already exists for this email' }
      );
    }

    const passwordHash = await hashPassword(password);

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, role, locked)
      VALUES (?, ?, ?, 0)
    `).run(email, passwordHash, role);

    writeAuditLog({
      userId: result.lastInsertRowid,
      action: 'register_success',
      resource: 'users',
      resourceId: result.lastInsertRowid,
      ipAddress
    });

    return respond(
      req,
      res,
      201,
      {
        success: true,
        message: 'User registered successfully',
        user: {
          id: result.lastInsertRowid,
          email,
          role
        }
      },
      'login',
      {
        success: 'Account created successfully. You can now sign in.'
      }
    );
  } catch (error) {
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const ipAddress = getClientIp(req);
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    const passwordMatches = await verifyPassword(
      password,
      user ? user.password_hash : DUMMY_HASH
    );

    if (!user) {
      writeAuditLog({
        action: 'login_failed_unknown_user',
        resource: 'auth',
        ipAddress
      });

      return respond(
        req,
        res,
        401,
        { success: false, message: INVALID_CREDENTIALS_MESSAGE },
        'login',
        { error: INVALID_CREDENTIALS_MESSAGE }
      );
    }

    const lockedUntil = user.locked_until ? new Date(user.locked_until) : null;
    if (lockedUntil && lockedUntil > new Date()) {
      writeAuditLog({
        userId: user.id,
        action: 'login_blocked_locked',
        resource: 'auth',
        resourceId: user.id,
        ipAddress
      });

      return respond(
        req,
        res,
        429,
        {
          success: false,
          message: 'Too many failed login attempts. Try again later.'
        },
        'login',
        { error: 'Too many failed login attempts. Try again later.' }
      );
    }

    if (!passwordMatches) {
      const failedAttempts = user.failed_login_attempts + 1;
      const shouldLock = failedAttempts >= HASH_CONFIG.maxFailedAttempts;

      db.prepare(`
        UPDATE users
        SET failed_login_attempts = ?,
            last_failed_login_at = CURRENT_TIMESTAMP,
            locked = ?,
            locked_until = CASE
              WHEN ? = 1
                THEN DATETIME('now', '+' || ? || ' minutes')
              ELSE NULL
            END
        WHERE id = ?
      `).run(
        failedAttempts,
        shouldLock ? 1 : 0,
        shouldLock ? 1 : 0,
        HASH_CONFIG.lockMinutes,
        user.id
      );

      writeAuditLog({
        userId: user.id,
        action: shouldLock ? 'login_failed_account_locked' : 'login_failed',
        resource: 'auth',
        resourceId: user.id,
        ipAddress
      });

      return respond(
        req,
        res,
        shouldLock ? 429 : 401,
        {
          success: false,
          message: shouldLock
            ? 'Too many failed login attempts. Try again later.'
            : INVALID_CREDENTIALS_MESSAGE
        },
        'login',
        {
          error: shouldLock
            ? 'Too many failed login attempts. Try again later.'
            : INVALID_CREDENTIALS_MESSAGE
        }
      );
    }

    db.prepare(`
      UPDATE users
      SET failed_login_attempts = 0,
          last_failed_login_at = NULL,
          locked = 0,
          locked_until = NULL
      WHERE id = ?
    `).run(user.id);

    await regenerateSession(req);

    req.session.user = {
      id: user.id,
      email: user.email,
      role: user.role
    };

    await saveSession(req);

    writeAuditLog({
      userId: user.id,
      action: 'login_success',
      resource: 'auth',
      resourceId: user.id,
      ipAddress
    });

    if (isJsonRequest(req)) {
      return res.status(200).json({
        success: true,
        message: 'Login successful',
        user: req.session.user
      });
    }

    return res.redirect('/dashboard');
  } catch (error) {
    return next(error);
  }
});

router.get('/me', requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    user: req.session.user
  });
});

router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    const ipAddress = getClientIp(req);
    const userId = req.session.user.id;

    writeAuditLog({
      userId,
      action: 'logout',
      resource: 'auth',
      resourceId: userId,
      ipAddress
    });

    await destroySession(req);
    res.clearCookie('authx.sid');

    if (isJsonRequest(req)) {
      return res.status(200).json({
        success: true,
        message: 'Logout successful'
      });
    }

    return res.redirect('/login');
  } catch (error) {
    return next(error);
  }
});

router.post('/forgot-password', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const ipAddress = getClientIp(req);
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    let resetToken = null;

    if (user) {
      resetToken = generateResetToken();
      const resetTokenHash = hashResetToken(resetToken);

      db.prepare(`
        UPDATE password_reset_tokens
        SET used_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND used_at IS NULL
      `).run(user.id);

      db.prepare(`
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used_at)
        VALUES (?, ?, DATETIME('now', '+' || ? || ' minutes'), NULL)
      `).run(user.id, resetTokenHash, HASH_CONFIG.resetTokenMinutes);

      writeAuditLog({
        userId: user.id,
        action: 'password_reset_requested',
        resource: 'auth',
        resourceId: user.id,
        ipAddress
      });
    } else {
      writeAuditLog({
        action: 'password_reset_requested_unknown_user',
        resource: 'auth',
        ipAddress
      });
    }

    return respond(
      req,
      res,
      200,
      {
        success: true,
        message: RESET_REQUEST_MESSAGE,
        resetToken
      },
      'forgot-password',
      {
        success: RESET_REQUEST_MESSAGE,
        resetToken
      }
    );
  } catch (error) {
    return next(error);
  }
});

router.post('/reset-password', async (req, res, next) => {
  try {
    const token = String(req.body.token || '').trim();
    const newPassword = String(req.body.newPassword || '');
    const ipAddress = getClientIp(req);

    const passwordPolicyError = validatePasswordPolicy(newPassword);
    if (!token || passwordPolicyError) {
      return respond(
        req,
        res,
        400,
        {
          success: false,
          message: passwordPolicyError || 'Token and password are required'
        },
        'reset-password',
        { error: passwordPolicyError || 'Token and password are required' }
      );
    }

    const resetEntry = db.prepare(`
      SELECT * FROM password_reset_tokens
      WHERE token_hash = ?
        AND used_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP
      ORDER BY id DESC
      LIMIT 1
    `).get(hashResetToken(token));

    if (!resetEntry) {
      return respond(
        req,
        res,
        400,
        { success: false, message: 'Invalid or expired reset token' },
        'reset-password',
        { error: 'Invalid or expired reset token' }
      );
    }

    const newPasswordHash = await hashPassword(newPassword);

    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          failed_login_attempts = 0,
          locked = 0,
          locked_until = NULL,
          last_failed_login_at = NULL
      WHERE id = ?
    `).run(newPasswordHash, resetEntry.user_id);

    db.prepare(`
      UPDATE password_reset_tokens
      SET used_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(resetEntry.id);

    writeAuditLog({
      userId: resetEntry.user_id,
      action: 'password_reset_completed',
      resource: 'auth',
      resourceId: resetEntry.user_id,
      ipAddress
    });

    return respond(
      req,
      res,
      200,
      { success: true, message: 'Password reset successful' },
      'login',
      { success: 'Password reset successful. You can now sign in.' }
    );
  } catch (error) {
    return next(error);
  }
});

router.get('/dashboard', requireAuth, (req, res) => {
  const search = sanitizeLikeInput(req.query.q);
  const tickets = getTicketsForUser(req.session.user, search);

  writeAuditLog({
    userId: req.session.user.id,
    action: search ? 'ticket_search' : 'dashboard_view',
    resource: 'tickets',
    ipAddress: getClientIp(req)
  });

  return res.render('dashboard', {
    user: req.session.user,
    tickets,
    search
  });
});

router.post('/tickets', requireAuth, (req, res) => {
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const severity = String(req.body.severity || 'LOW');

  if (!title || !description) {
    return res.status(400).render('dashboard', {
      user: req.session.user,
      tickets: getTicketsForUser(req.session.user),
      search: '',
      error: 'Title and description are required.'
    });
  }

  const allowedSeverities = new Set(['LOW', 'MED', 'HIGH']);
  const safeSeverity = allowedSeverities.has(severity) ? severity : 'LOW';

  const result = db.prepare(`
    INSERT INTO tickets (title, description, severity, status, owner_id)
    VALUES (?, ?, ?, 'OPEN', ?)
  `).run(title, description, safeSeverity, req.session.user.id);

  writeAuditLog({
    userId: req.session.user.id,
    action: 'ticket_created',
    resource: 'tickets',
    resourceId: result.lastInsertRowid,
    ipAddress: getClientIp(req)
  });

  return res.redirect('/dashboard');
});

router.get('/tickets/:id', requireAuth, (req, res) => {
  const ticketId = Number(req.params.id);

  if (!Number.isInteger(ticketId) || ticketId <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid ticket id'
    });
  }

  const ticket = getTicketByIdForUser(ticketId, req.session.user);

  if (!ticket) {
    writeAuditLog({
      userId: req.session.user.id,
      action: 'ticket_access_denied',
      resource: 'tickets',
      resourceId: ticketId,
      ipAddress: getClientIp(req)
    });

    return res.status(404).json({
      success: false,
      message: 'Ticket not found'
    });
  }

  writeAuditLog({
    userId: req.session.user.id,
    action: 'ticket_viewed',
    resource: 'tickets',
    resourceId: ticketId,
    ipAddress: getClientIp(req)
  });

  return res.status(200).json({
    success: true,
    ticket
  });
});

router.get('/audit-logs', requireAuth, (req, res) => {
  if (req.session.user.role !== 'MANAGER') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden'
    });
  }

  const logs = db.prepare(`
    SELECT audit_logs.*, users.email
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.user_id
    ORDER BY audit_logs.timestamp DESC, audit_logs.id DESC
    LIMIT 50
  `).all();

  return res.status(200).json({
    success: true,
    logs
  });
});

router.get('/debug/session', requireAuth, (req, res) => {
  const cookieHeader = Object.entries(req.session.cookie || {})
    .filter(([key]) => !key.startsWith('_'))
    .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});

  return res.status(200).json({
    success: true,
    cookie: cookieHeader
  });
});

module.exports = router;
