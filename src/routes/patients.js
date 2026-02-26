const express = require('express');
const router = express.Router();
const db = require('../utils/database');

// FIX: SQL Injection (CWE-89) — All queries are pre-prepared at module level
// with named placeholders. User data ONLY flows into bound parameters, never
// into query strings. This eliminates CWE-089/090/943 (CodeQL alerts #27-#33).
const searchPatientsStmt = db.prepare('SELECT * FROM patients WHERE name LIKE @searchName');
const getPatientStmt = db.prepare('SELECT * FROM patients WHERE id = @patientId');
const insertPatientStmt = db.prepare('INSERT INTO patients (name, dob, ssn, diagnosis) VALUES (@name, @dob, @ssn, @diagnosis)');
const updatePatientStmt = db.prepare('UPDATE patients SET diagnosis = @diagnosis WHERE id = @id');
const deletePatientStmt = db.prepare('DELETE FROM patients WHERE id = @id');
const updateNameStmt = db.prepare('UPDATE patients SET name = @value WHERE id = @id');
const updateDobStmt = db.prepare('UPDATE patients SET dob = @value WHERE id = @id');
const updateSsnStmt = db.prepare('UPDATE patients SET ssn = @value WHERE id = @id');
const updateDiagnosisStmt = db.prepare('UPDATE patients SET diagnosis = @value WHERE id = @id');
const COLUMN_STATEMENTS = { name: updateNameStmt, dob: updateDobStmt, ssn: updateSsnStmt, diagnosis: updateDiagnosisStmt };

router.get('/search', (req, res) => {
  const name = req.query.name;
  const results = searchPatientsStmt.all({ searchName: '%' + name + '%' });
  res.json(results);
});

router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const patient = getPatientStmt.get({ patientId });
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  insertPatientStmt.run({ name, dob, ssn, diagnosis });
  res.json({ message: 'Patient added successfully' });
});

router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  updatePatientStmt.run({ diagnosis, id });
  res.json({ message: 'Patient updated' });
});

router.delete('/:id', (req, res) => {
  const id = req.params.id;
  deletePatientStmt.run({ id });
  res.json({ message: 'Patient deleted' });
});

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
