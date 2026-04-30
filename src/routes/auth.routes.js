const express = require('express');
const db = require('../db/connection');

const router = express.Router();

function isJsonRequest(req) {
  const contentType = req.headers['content-type'] || '';
  const accept = req.headers.accept || '';
  return contentType.includes('application/json') || accept.includes('application/json');
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (isJsonRequest(req)) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated'
      });
    }

    return res.redirect('/login');
  }

  return next();
}

function getTickets(searchTerm = '') {
  const search = String(searchTerm || '').trim();
  const pattern = `%${search}%`;

  return db.prepare(`
    SELECT tickets.*, users.email AS owner_email
    FROM tickets
    JOIN users ON users.id = tickets.owner_id
    WHERE (? = '' OR tickets.title LIKE ? OR tickets.description LIKE ?)
    ORDER BY tickets.created_at DESC, tickets.id DESC
  `).all(search, pattern, pattern);
}

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

  if (!isJsonRequest(req)) {
    return res.redirect('/login');
  }

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

  if (!isJsonRequest(req)) {
    return res.redirect('/dashboard');
  }

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

    if (!isJsonRequest(req)) {
      return res.redirect('/login');
    }

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

router.get('/dashboard', requireAuth, (req, res) => {
  const search = String(req.query.q || '').trim();

  return res.render('dashboard', {
    user: req.session.user,
    tickets: getTickets(search),
    search
  });
});

router.post('/tickets', requireAuth, (req, res) => {
  const { title, description, severity } = req.body;

  if (!title || !description) {
    return res.status(400).render('dashboard', {
      user: req.session.user,
      tickets: getTickets(),
      search: '',
      error: 'Title and description are required.'
    });
  }

  db.prepare(`
    INSERT INTO tickets (title, description, severity, status, owner_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, description, severity || 'LOW', 'OPEN', req.session.user.id);

  return res.redirect('/dashboard');
});

router.get('/tickets/:id', requireAuth, (req, res) => {
  const ticket = db.prepare(`
    SELECT tickets.*, users.email AS owner_email
    FROM tickets
    JOIN users ON users.id = tickets.owner_id
    WHERE tickets.id = ?
  `).get(req.params.id);

  if (!ticket) {
    return res.status(404).json({
      success: false,
      message: 'Ticket not found'
    });
  }

  return res.status(200).json({
    success: true,
    ticket
  });
});

module.exports = router;
