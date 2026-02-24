const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'monthly', 'quarterly', 'annual', 'patient', 'billing', 'audit'];

// Allowlist of valid export formats
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];

// Strict pattern for filenames: alphanumeric, hyphens, underscores, dots only
const SAFE_FILENAME_PATTERN = /^[a-zA-Z0-9._-]+$/;

// Strict pattern for file paths: alphanumeric, hyphens, underscores, dots, forward slashes only
const SAFE_FILEPATH_PATTERN = /^[a-zA-Z0-9._/\-]+$/;

// FIX: Use execFileSync with arguments array + input validation to prevent command injection (CWE-78)
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || !ALLOWED_REPORT_TYPES.includes(reportType)) {
    return res.status(400).json({ error: 'Invalid report type. Allowed types: ' + ALLOWED_REPORT_TYPES.join(', ') });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIX: Use execFile with arguments array + input validation to prevent command injection (CWE-78)
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || !SAFE_FILENAME_PATTERN.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, dots, hyphens, and underscores are allowed.' });
  }
  if (!format || !ALLOWED_EXPORT_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'Invalid format. Allowed formats: ' + ALLOWED_EXPORT_FORMATS.join(', ') });
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

// FIX: Use execFileSync with arguments array + input validation to prevent command injection (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files must be a non-empty array.' });
  }
  for (const file of files) {
    if (typeof file !== 'string' || !SAFE_FILEPATH_PATTERN.test(file)) {
      return res.status(400).json({ error: 'Invalid file path: ' + String(file) + '. Only alphanumeric characters, dots, hyphens, underscores, and forward slashes are allowed.' });
    }
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
