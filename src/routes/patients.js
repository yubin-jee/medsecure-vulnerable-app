const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const db = require('../utils/database');

// Rate limiter for patient routes: max 100 requests per 15 minutes per IP
const patientRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Apply rate limiting to all patient routes
router.use(patientRateLimiter);

// Allowed columns for patient updates (whitelist to prevent SQL injection via column names)
const ALLOWED_PATIENT_COLUMNS = ['name', 'dob', 'ssn', 'diagnosis'];

// FIXED: SQL Injection - use parameterized query with ? placeholder
// Rate limited via router-level middleware above
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE ?";
  const results = db.prepare(query).all(`%${name}%`);
  res.json(results);
});

// FIXED: SQL Injection - use parameterized query with ? placeholder
router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const query = "SELECT * FROM patients WHERE id = ?";
  const patient = db.prepare(query).get(patientId);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// FIXED: SQL Injection - use parameterized query with ? placeholders
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)";
  db.prepare(query).run(name, dob, ssn, diagnosis);
  res.json({ message: 'Patient added successfully' });
});

// FIXED: SQL Injection - use parameterized query with ? placeholders
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = ? WHERE id = ?";
  db.prepare(query).run(diagnosis, id);
  res.json({ message: 'Patient updated' });
});

// FIXED: SQL Injection - use parameterized query with ? placeholder
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
  res.json({ message: 'Patient deleted' });
});

// FIXED: SQL Injection - use parameterized queries with whitelisted column names
router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    const entries = Object.entries(update).filter(([key]) => key !== 'id');
    // Whitelist column names to prevent injection via dynamic keys
    const safeEntries = entries.filter(([key]) => ALLOWED_PATIENT_COLUMNS.includes(key));
    if (safeEntries.length === 0) return;
    const setClauses = safeEntries.map(([key]) => `${key} = ?`).join(', ');
    const values = safeEntries.map(([, val]) => val);
    values.push(update.id);
    db.prepare(`UPDATE patients SET ${setClauses} WHERE id = ?`).run(...values);
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
