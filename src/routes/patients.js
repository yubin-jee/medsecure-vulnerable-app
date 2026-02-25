const express = require('express');
const router = express.Router();
const db = require('../utils/database');

// FIXED: SQL Injection (CWE-89) - use parameterized query
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE ?";
  const results = db.prepare(query).all(`%${name}%`);
  res.json(results);
});

// FIXED: SQL Injection (CWE-89) - use parameterized query
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
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = "INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (?, ?, ?, ?)";
  db.prepare(query).run(name, dob, ssn, diagnosis);
  res.json({ message: 'Patient added successfully' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized query in UPDATE
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = ? WHERE id = ?";
  db.prepare(query).run(diagnosis, id);
  res.json({ message: 'Patient updated' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized query in DELETE
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = ?").run(id);
  res.json({ message: 'Patient deleted' });
});

// FIXED: SQL Injection (CWE-89) - use parameterized queries in bulk update
// Column names are sourced from this constant array (never from user input)
const ALLOWED_COLUMNS = ['name', 'dob', 'ssn', 'diagnosis'];

router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    // Only include columns from the hardcoded allowlist that exist in the update
    const columnsToUpdate = ALLOWED_COLUMNS.filter(col => Object.prototype.hasOwnProperty.call(update, col));
    if (columnsToUpdate.length === 0) return;
    const setClauses = columnsToUpdate.map(col => `${col} = ?`).join(', ');
    const values = columnsToUpdate.map(col => update[col]);
    values.push(update.id);
    db.prepare(`UPDATE patients SET ${setClauses} WHERE id = ?`).run(...values);
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
