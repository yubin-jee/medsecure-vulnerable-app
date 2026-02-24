const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../utils/database');

// VULN: Hardcoded credentials (CWE-798)
const JWT_SECRET = 'supersecretkey123';
const ADMIN_PASSWORD = 'admin123!';
const DB_PASSWORD = 'postgres://admin:password123@db.medsecure.internal:5432/patients';

// VULN: SQL Injection in login (CWE-89)
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  const user = db.prepare(query).get();

  if (user) {
    // VULN: Weak cryptographic algorithm (CWE-327) - MD5 for token generation
    const token = crypto.createHash('md5').update(user.id + Date.now().toString()).digest('hex');

    // VULN: JWT with hardcoded secret
    const jwtToken = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET);

    res.json({ token, jwtToken });
  } else {
    // VULN: Information exposure through error message (CWE-209)
    res.status(401).json({
      error: 'Login failed',
      debug: `Query executed: ${query}`,
      server: process.env.HOSTNAME,
      dbConnection: DB_PASSWORD
    });
  }
});

// VULN: Insecure randomness (CWE-330) - Math.random for password reset token
router.post('/reset-password', (req, res) => {
  const { email } = req.body;
  const resetToken = Math.random().toString(36).substring(2);
  const expiry = Date.now() + 3600000;

  db.prepare(`UPDATE users SET reset_token = '${resetToken}', reset_expiry = ${expiry} WHERE email = '${email}'`).run();

  res.json({ message: 'Password reset email sent', token: resetToken });
});

// VULN: Missing authentication on sensitive endpoint
router.get('/users', (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, ssn FROM users').all();
  res.json(users);
});

// VULN: Cleartext storage of password (CWE-312)
router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  db.prepare(`INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`).run();
  res.json({ message: 'User registered' });
});

module.exports = router;
