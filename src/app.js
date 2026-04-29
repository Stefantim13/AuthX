const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/auth.routes');

const app = express();
const PORT = 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

app.use(
  session({
    name: 'authx.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 15
    }
  })
);

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.use('/', authRoutes);

app.use((err, req, res, next) => {
  console.error(err);

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.status(500).json({
      success: false,
      message: 'An unexpected error occurred'
    });
  }

  return res.status(500).render('error', {
    message: 'An unexpected error occurred'
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
