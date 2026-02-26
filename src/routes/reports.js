const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - validate input and use execFileSync with argument array
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'financial'];
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || !ALLOWED_REPORT_TYPES.includes(reportType)) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - validate input and use execFile with argument array
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];
const SAFE_FILENAME_RE = /^[a-zA-Z0-9._-]+$/;
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || !SAFE_FILENAME_RE.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  if (!format || !ALLOWED_EXPORT_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'Invalid export format' });
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

// FIXED: Command injection via filename (CWE-78) - validate input, use execFileSync with argument array and '--' separator
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files array is required' });
  }
  const sanitizedFiles = files.filter((f) => typeof f === 'string' && SAFE_FILENAME_RE.test(f));
  if (sanitizedFiles.length !== files.length) {
    return res.status(400).json({ error: 'One or more filenames are invalid' });
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', '--', ...sanitizedFiles]);
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
