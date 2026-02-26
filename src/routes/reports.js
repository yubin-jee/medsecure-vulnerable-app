const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIX: Use execFileSync with argument array to prevent command injection (CWE-78)
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || !/^[a-zA-Z0-9_-]+$/.test(reportType)) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIX: Use execFile with argument array to prevent command injection (CWE-78)
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || !format || !/^[a-zA-Z0-9_.\-/]+$/.test(filename) || !/^[a-zA-Z0-9_-]+$/.test(format)) {
    return res.status(400).json({ error: 'Invalid filename or format' });
  }
  execFile('convert-data', [filename, '--output-format', format], (err, stdout) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// VULN: Path traversal (CWE-22) - user controls file path
router.get('/download', (req, res) => {
  const filename = req.query.file;
  const filePath = path.join('/reports', filename);
  res.sendFile(filePath);
});

// VULN: Path traversal (CWE-22) - reading arbitrary files
router.get('/view', (req, res) => {
  const reportPath = req.query.path;
  const content = fs.readFileSync(reportPath, 'utf-8');
  res.json({ content });
});

// FIX: Use execFileSync with argument array to prevent command injection (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0 || !files.every(f => /^[a-zA-Z0-9_.\-/]+$/.test(f))) {
    return res.status(400).json({ error: 'Invalid file list' });
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...files]);
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
