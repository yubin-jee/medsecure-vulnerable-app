const express = require('express');
const router = express.Router();
const db = require('../utils/database');

// FIX: SQL Injection (CWE-89) - use parameterized query with named bound parameter
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE @searchName";
  const results = db.prepare(query).all({ searchName: '%' + name + '%' });
  res.json(results);
});

// FIX: SQL Injection (CWE-89) - use parameterized query with named bound parameter
router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const query = "SELECT * FROM patients WHERE id = @patientId";
  const patient = db.prepare(query).get({ patientId });
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// FIX: SQL Injection (CWE-89) - use parameterized query with named bound parameters
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (@name, @dob, @ssn, @diagnosis)";
  db.prepare(query).run({ name, dob, ssn, diagnosis });
  res.json({ message: 'Patient added successfully' });
});

// FIX: SQL Injection (CWE-89) - use parameterized query with named bound parameters
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = @diagnosis WHERE id = @id";
  db.prepare(query).run({ diagnosis, id });
  res.json({ message: 'Patient updated' });
});

// FIX: SQL Injection (CWE-89) - use parameterized query with named bound parameter
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = @id").run({ id });
  res.json({ message: 'Patient deleted' });
});

// FIX: SQL Injection (CWE-89) - use individual prepared statements with hardcoded queries
// Each allowed column has its own pre-built prepared statement; no dynamic SQL construction
const updateName = db.prepare('UPDATE patients SET name = @value WHERE id = @id');
const updateDob = db.prepare('UPDATE patients SET dob = @value WHERE id = @id');
const updateSsn = db.prepare('UPDATE patients SET ssn = @value WHERE id = @id');
const updateDiagnosis = db.prepare('UPDATE patients SET diagnosis = @value WHERE id = @id');
const COLUMN_STATEMENTS = { name: updateName, dob: updateDob, ssn: updateSsn, diagnosis: updateDiagnosis };

router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    for (const [col, stmt] of Object.entries(COLUMN_STATEMENTS)) {
      if (Object.prototype.hasOwnProperty.call(update, col)) {
        stmt.run({ value: update[col], id: update.id });
      }
    }
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
