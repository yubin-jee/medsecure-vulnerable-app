const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'patient', 'billing'];

// Allowlist of valid export formats
const ALLOWED_FORMATS = ['pdf', 'csv', 'json', 'xml', 'html'];

// Validate that a value contains only safe characters (alphanumeric, hyphens, underscores, dots)
function isSafeFilename(value) {
  return /^[a-zA-Z0-9._-]+$/.test(value);
}

router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!ALLOWED_REPORT_TYPES.includes(reportType)) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || !isSafeFilename(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  if (!ALLOWED_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'Invalid format' });
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

router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files must be a non-empty array' });
  }
  const invalidFiles = files.filter((f) => !isSafeFilename(f));
  if (invalidFiles.length > 0) {
    return res.status(400).json({ error: 'Invalid filename(s) detected' });
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
