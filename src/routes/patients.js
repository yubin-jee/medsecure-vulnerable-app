const express = require('express');
const router = express.Router();
const db = require('../utils/database');

// VULN: SQL Injection (CWE-89) - user input concatenated into query
router.get('/search', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM patients WHERE name LIKE '%" + name + "%'";
  const results = db.prepare(query).all();
  res.json(results);
});

// VULN: SQL Injection (CWE-89) - template literal injection
router.get('/:id', (req, res) => {
  const patientId = req.params.id;
  const query = `SELECT * FROM patients WHERE id = ${patientId}`;
  const patient = db.prepare(query).get();
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }
  res.json(patient);
});

// VULN: SQL Injection (CWE-89) - in INSERT statement
router.post('/', (req, res) => {
  const { name, dob, ssn, diagnosis } = req.body;
  const query = `INSERT INTO patients (name, dob, ssn, diagnosis) VALUES ('${name}', '${dob}', '${ssn}', '${diagnosis}')`;
  db.prepare(query).run();
  res.json({ message: 'Patient added successfully' });
});

// VULN: SQL Injection (CWE-89) - in UPDATE
router.put('/:id', (req, res) => {
  const { diagnosis } = req.body;
  const id = req.params.id;
  const query = "UPDATE patients SET diagnosis = '" + diagnosis + "' WHERE id = " + id;
  db.prepare(query).run();
  res.json({ message: 'Patient updated' });
});

// VULN: SQL Injection (CWE-89) - in DELETE
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM patients WHERE id = " + id).run();
  res.json({ message: 'Patient deleted' });
});

// VULN: Mass assignment / Insecure direct object reference
router.post('/bulk-update', (req, res) => {
  const updates = req.body;
  updates.forEach(update => {
    const setClauses = Object.entries(update)
      .filter(([key]) => key !== 'id')
      .map(([key, val]) => `${key} = '${val}'`)
      .join(', ');
    db.prepare(`UPDATE patients SET ${setClauses} WHERE id = ${update.id}`).run();
  });
  res.json({ message: 'Bulk update complete' });
});

module.exports = router;
