const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const db = require('../utils/database');

// Rate limiter for patient routes to prevent abuse
const patientRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

router.use(patientRateLimiter);

// FIXED: SQL Injection (CWE-89) - use parameterized query
// Rate limiting applied via router-level middleware above
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE ?";
  const results = db.prepare(query).all(`%${name}%`);
  res.json(results);
});

// FIXED: SQL Injection (CWE-89) - use parameterized query
// Rate limiting applied via router-level middleware above
router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const query = "SELECT * FROM patients WHERE id = ?";
  const patient = db.prepare(query).get(patientId);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// FIXED: SQL Injection (CWE-89) - use parameterized query in INSERT
// Rate limiting applied via router-level middleware above
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)";
  db.prepare(query).run(name, dob, ssn, diagnosis);
  res.json({ message: 'Patient added successfully' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized query in UPDATE
// Rate limiting applied via router-level middleware above
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = ? WHERE id = ?";
  db.prepare(query).run(diagnosis, id);
  res.json({ message: 'Patient updated' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized query in DELETE
// Rate limiting applied via router-level middleware above
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
  res.json({ message: 'Patient deleted' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized queries with whitelisted columns
const ALLOWED_PATIENT_COLUMNS = new Set(['name', 'dob', 'ssn', 'diagnosis']);

router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    const entries = Object.entries(update).filter(([key]) => key !== 'id' && ALLOWED_PATIENT_COLUMNS.has(key));
    if (entries.length === 0) return;
    const setClauses = entries.map(([key]) => `${key} = ?`).join(', ');
    const values = entries.map(([, val]) => val);
    values.push(update.id);
    db.prepare(`UPDATE patients SET ${setClauses} WHERE id = ?`).run(...values);
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
