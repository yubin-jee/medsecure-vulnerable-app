const express = require('express');
const router = express.Router();
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// VULN: Command injection (CWE-78) - user input in shell command
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const output = execSync('generate-report --type ' + reportType + ' --format pdf');
  res.send(output);
});

// VULN: Command injection (CWE-78) - template literal in exec
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  exec(`convert-data "${filename}" --output-format ${format}`, (err, stdout) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// FIX: Path traversal (CWE-22) - normalize and reject paths containing '..'
router.get('/download', (req, res) => {
  const filename = req.query.file;
  if (!filename) {
    return res.status(400).json({ error: 'Missing file parameter' });
  }
  const normalized = path.normalize(filename);
  if (normalized.includes('..')) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(normalized, { root: path.resolve('/reports') });
});

// FIX: Path traversal (CWE-22) - normalize and reject paths containing '..'
router.get('/view', (req, res) => {
  const reportPath = req.query.path;
  if (!reportPath) {
    return res.status(400).json({ error: 'Missing path parameter' });
  }
  const normalized = path.normalize(reportPath);
  if (normalized.includes('..')) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const safePath = path.join(path.resolve('/reports'), normalized);
  const content = fs.readFileSync(safePath, 'utf-8');
  res.json({ content });
});

// VULN: Command injection via filename (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  const fileList = files.join(' ');
  execSync(`tar -czf /tmp/archive.tar.gz ${fileList}`);
  res.download('/tmp/archive.tar.gz');
});

// VULN: Server-Side Request Forgery (CWE-918)
const http = require('http');
router.get('/fetch-external', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  });
});

module.exports = router;
