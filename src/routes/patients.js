const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const db = require('../utils/database');

// Rate limiter for patient routes to prevent abuse (CWE-770)
const patientRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

router.use(patientRateLimiter);

// FIX: SQL Injection (CWE-89) - use parameterized query instead of concatenation
// Rate limiting applied via router.use(patientRateLimiter) above
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE ?";
  const results = db.prepare(query).all(`%${name}%`);
  res.json(results);
});

// FIX: SQL Injection (CWE-89) - use parameterized query instead of template literal
router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const query = "SELECT * FROM patients WHERE id = ?";
  const patient = db.prepare(query).get(patientId);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// FIX: SQL Injection (CWE-89) - use parameterized query for INSERT
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)";
  db.prepare(query).run(name, dob, ssn, diagnosis);
  res.json({ message: 'Patient added successfully' });
});

// FIX: SQL Injection (CWE-89) - use parameterized query for UPDATE
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = ? WHERE id = ?";
  db.prepare(query).run(diagnosis, id);
  res.json({ message: 'Patient updated' });
});

// FIX: SQL Injection (CWE-89) - use parameterized query for DELETE
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
  res.json({ message: 'Patient deleted' });
});

// FIX: SQL Injection (CWE-89) - use parameterized queries with static column allowlist for bulk update
// Column names are drawn from a static array (never from user input) to prevent injection.
const ALLOWED_PATIENT_COLUMNS = ['name', 'dob', 'ssn', 'diagnosis'];

router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    const setClauses = [];
    const values = [];
    for (const col of ALLOWED_PATIENT_COLUMNS) {
      if (Object.prototype.hasOwnProperty.call(update, col)) {
        setClauses.push(col + ' = ?');
        values.push(update[col]);
      }
    }
    if (setClauses.length === 0) return;
    values.push(update.id);
    db.prepare('UPDATE patients SET ' + setClauses.join(', ') + ' WHERE id = ?').run(...values);
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
