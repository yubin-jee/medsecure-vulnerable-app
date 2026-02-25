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

// FIXED: SQL Injection (CWE-89) - fully static parameterized query for bulk update
// COALESCE keeps existing value when parameter is null (column not being updated)
const BULK_UPDATE_QUERY = "UPDATE patients SET name = COALESCE(?, name), dob = COALESCE(?, dob), ssn = COALESCE(?, ssn), diagnosis = COALESCE(?, diagnosis) WHERE id = ?";

router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  const stmt = db.prepare(BULK_UPDATE_QUERY);
  updates.forEach(update => {
    stmt.run(
      Object.prototype.hasOwnProperty.call(update, 'name') ? update.name : null,
      Object.prototype.hasOwnProperty.call(update, 'dob') ? update.dob : null,
      Object.prototype.hasOwnProperty.call(update, 'ssn') ? update.ssn : null,
      Object.prototype.hasOwnProperty.call(update, 'diagnosis') ? update.diagnosis : null,
      update.id
    );
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
