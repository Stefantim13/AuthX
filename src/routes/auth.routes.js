const express = require('express');
const db = require('../db/connection');

const router = express.Router();

router.get('/login', (req, res) => {
  res.render('login', {
    error: null,
    success: null
  });
});

router.get('/register', (req, res) => {
  res.render('register', {
    error: null,
    success: null
  });
});

router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', {
    error: null,
    success: null,
    resetToken: null
  });
});

router.get('/reset-password', (req, res) => {
  res.render('reset-password', {
    error: null,
    success: null
  });
});

router.post('/register', (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }

  const existingUser = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email);

  if (existingUser) {
    return res.status(409).json({
      success: false,
      message: 'User already exists'
    });
  }

  const userRole = role || 'ANALYST';

  const result = db.prepare(`
    INSERT INTO users (email, password_hash, role, locked)
    VALUES (?, ?, ?, ?)
  `).run(email, password, userRole, 0);

  return res.status(201).json({
    success: true,
    message: 'User registered successfully',
    user: {
      id: result.lastInsertRowid,
      email,
      role: userRole
    }
  });
});

router.post('/login', (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User does not exist'
    });
  }

  if (user.password_hash !== password) {
    return res.status(401).json({
      success: false,
      message: 'Incorrect password'
    });
  }

  req.session.user = {
    id: user.id,
    email: user.email,
    role: user.role
  };

  return res.status(200).json({
    success: true,
    message: 'Login successful',
    user: req.session.user
  });
});

router.get('/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: 'Not authenticated'
    });
  }

  return res.status(200).json({
    success: true,
    user: req.session.user
  });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    return res.status(200).json({
      success: true,
      message: 'Logout successful'
    });
  });
});

router.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Email is required'
    });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User does not exist'
    });
  }

  const token = `reset-${user.id}`;

  db.prepare(`
    INSERT INTO password_reset_tokens (user_id, token, expires_at, used_at)
    VALUES (?, ?, ?, ?)
  `).run(user.id, token, null, null);

  return res.status(200).json({
    success: true,
    message: 'Password reset token generated',
    resetToken: token
  });
});

router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({
      success: false,
      message: 'Token and newPassword are required'
    });
  }

  const resetEntry = db.prepare(`
    SELECT * FROM password_reset_tokens
    WHERE token = ?
    ORDER BY id DESC
    LIMIT 1
  `).get(token);

  if (!resetEntry) {
    return res.status(404).json({
      success: false,
      message: 'Invalid reset token'
    });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(resetEntry.user_id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'Associated user not found'
    });
  }

  db.prepare(`
    UPDATE users
    SET password_hash = ?
    WHERE id = ?
  `).run(newPassword, user.id);

  db.prepare(`
    UPDATE password_reset_tokens
    SET used_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(resetEntry.id);

  return res.status(200).json({
    success: true,
    message: 'Password reset successful'
  });
});

module.exports = router;
