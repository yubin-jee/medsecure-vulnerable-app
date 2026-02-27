const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const db = require('../utils/database');

// Allowed columns for the patients table (used to whitelist dynamic column names)
const ALLOWED_PATIENT_COLUMNS = new Set(['name', 'dob', 'ssn', 'diagnosis']);

// Rate limiter for patient routes
const patientRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Fixed: Use parameterized query to prevent SQL injection
router.get('/search', patientRateLimiter, (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE ?";
  const results = db.prepare(query).all(`%${name}%`);
  res.json(results);
});

// Fixed: Use parameterized query to prevent SQL injection
router.get('/:id', patientRateLimiter, (req, res) => {
  const patientId = req.params.id;
  const query = "SELECT * FROM patients WHERE id = ?";
  const patient = db.prepare(query).get(patientId);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// Fixed: Use parameterized query to prevent SQL injection
router.post('/', patientRateLimiter, (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)";
  db.prepare(query).run(name, dob, ssn, diagnosis);
  res.json({ message: 'Patient added successfully' });
});

// Fixed: Use parameterized query to prevent SQL injection
router.put('/:id', patientRateLimiter, (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = ? WHERE id = ?";
  db.prepare(query).run(diagnosis, id);
  res.json({ message: 'Patient updated' });
});

// Fixed: Use parameterized query to prevent SQL injection
router.delete('/:id', patientRateLimiter, (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
  res.json({ message: 'Patient deleted' });
});

// Fixed: Whitelist column names and use parameterized query to prevent SQL injection
router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    const entries = Object.entries(update)
      .filter(([key]) => key !== 'id' && ALLOWED_PATIENT_COLUMNS.has(key));
    if (entries.length === 0) return;
    const setClauses = entries.map(([key]) => `${key} = ?`).join(', ');
    const values = entries.map(([, val]) => val);
    values.push(update.id);
    db.prepare(`UPDATE patients SET ${setClauses} WHERE id = ?`).run(...values);
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
