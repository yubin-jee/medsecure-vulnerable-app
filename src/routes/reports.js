const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - use execFileSync with argument array and input validation
const ALLOWED_REPORT_TYPES = ['pdf', 'csv', 'html', 'json', 'xml'];
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || !ALLOWED_REPORT_TYPES.includes(reportType)) {
    return res.status(400).json({ error: 'Invalid report type. Allowed: ' + ALLOWED_REPORT_TYPES.join(', ') });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - use execFile with argument array and input validation
const ALLOWED_EXPORT_FORMATS = ['pdf', 'csv', 'html', 'json', 'xml'];
const SAFE_FILENAME_PATTERN = /^[a-zA-Z0-9_][a-zA-Z0-9_.\-]*$/;
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || !SAFE_FILENAME_PATTERN.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
  }
  if (!format || !ALLOWED_EXPORT_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'Invalid format. Allowed: ' + ALLOWED_EXPORT_FORMATS.join(', ') });
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

// FIXED: Command injection via filename (CWE-78) - use execFileSync with argument array and input validation
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files must be a non-empty array' });
  }
  for (const file of files) {
    if (typeof file !== 'string' || !SAFE_FILENAME_PATTERN.test(file)) {
      return res.status(400).json({ error: 'Invalid filename: ' + String(file) + '. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
    }
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', '--', ...files]);
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
