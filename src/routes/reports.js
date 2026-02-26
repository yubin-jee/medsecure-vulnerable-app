const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - use execFileSync with argument array and input validation
const ALLOWED_REPORT_TYPES = ['pdf', 'csv', 'html', 'json', 'xml'];
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const typeIndex = ALLOWED_REPORT_TYPES.indexOf(reportType);
  if (!reportType || typeIndex === -1) {
    return res.status(400).json({ error: 'Invalid report type. Allowed: ' + ALLOWED_REPORT_TYPES.join(', ') });
  }
  const safeReportType = ALLOWED_REPORT_TYPES[typeIndex];
  const output = execFileSync('generate-report', ['--type', safeReportType, '--format', 'pdf']);
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
  const formatIndex = ALLOWED_EXPORT_FORMATS.indexOf(format);
  if (!format || formatIndex === -1) {
    return res.status(400).json({ error: 'Invalid format. Allowed: ' + ALLOWED_EXPORT_FORMATS.join(', ') });
  }
  // Derive safe values from constants/validated match to break taint chain
  const safeFilename = filename.match(SAFE_FILENAME_PATTERN)[0];
  const safeFormat = ALLOWED_EXPORT_FORMATS[formatIndex];
  execFile('convert-data', [safeFilename, '--output-format', safeFormat], (err, stdout) => {
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
  // Validate and derive safe filenames to break taint chain
  const safeFiles = [];
  for (const file of files) {
    if (typeof file !== 'string' || !SAFE_FILENAME_PATTERN.test(file)) {
      return res.status(400).json({ error: 'Invalid filename: ' + String(file) + '. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
    }
    safeFiles.push(file.match(SAFE_FILENAME_PATTERN)[0]);
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', '--', ...safeFiles]);
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
