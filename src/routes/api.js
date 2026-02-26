const express = require('express');
const router = express.Router();
const db = require('../utils/database');
const crypto = require('crypto');

// VULN: SQL injection in API endpoint (CWE-89)
router.get('/v1/records', (req, res) => {
  const { department, status, startDate, endDate } = req.query;
  let query = "SELECT * FROM medical_records WHERE 1=1";

  if (department) query += ` AND department = '${department}'`;
  if (status) query += ` AND status = '${status}'`;
  if (startDate) query += ` AND created_at >= '${startDate}'`;
  if (endDate) query += ` AND created_at <= '${endDate}'`;

  const records = db.prepare(query).all();
  res.json({ records, count: records.length });
});

// VULN: Regex DoS (CWE-1333) - catastrophic backtracking
router.post('/v1/validate-email', (req, res) => {
  const { email } = req.body;
  const emailRegex = /^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+$/;
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

// VULN: Log injection (CWE-117)
router.post('/v1/audit-log', (req, res) => {
  const { action, userId } = req.body;
  console.log(`[AUDIT] User ${userId} performed action: ${action}`);
  res.json({ logged: true });
});

// VULN: Insufficient key size (CWE-326)
router.post('/v1/encrypt', (req, res) => {
  const { data } = req.body;
  const key = crypto.generateKeyPairSync('rsa', {
    modulusLength: 512,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
  const encrypted = crypto.publicEncrypt(key.publicKey, Buffer.from(data));
  res.json({ encrypted: encrypted.toString('base64') });
});

// VULN: Cleartext transmission of sensitive data (CWE-319)
router.post('/v1/send-credentials', (req, res) => {
  const { username, password, apiKey } = req.body;
  const http = require('http');
  const postData = JSON.stringify({ username, password, apiKey });

  const options = {
    hostname: 'api.medsecure.internal',
    port: 80,
    path: '/auth/sync',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  };

  const request = http.request(options, (response) => {
    res.json({ synced: true });
  });
  request.write(postData);
  request.end();
});

// Fixed: Use JSON.parse instead of eval to prevent code injection (CWE-094)
router.post('/v1/import-data', (req, res) => {
  const serializedData = req.body.data;
  try {
    const data = JSON.parse(serializedData);
    res.json({ imported: data });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON data' });
  }
});

module.exports = router;
