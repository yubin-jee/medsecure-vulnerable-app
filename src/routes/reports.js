const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'patient', 'billing'];

// Allowlist of valid export formats
const ALLOWED_FORMATS = ['pdf', 'csv', 'json', 'xml', 'html'];

// Extract a sanitized filename containing only safe characters (alphanumeric, hyphens, underscores, dots)
// Returns the sanitized string or null if the value is invalid
function sanitizeFilename(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(/^[a-zA-Z0-9._-]+$/);
  return match ? match[0] : null;
}

router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const typeIndex = ALLOWED_REPORT_TYPES.indexOf(reportType);
  if (typeIndex === -1) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  // Use the allowlisted value to avoid passing tainted data to the command
  const safeType = ALLOWED_REPORT_TYPES[typeIndex];
  const output = execFileSync('generate-report', ['--type', safeType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = sanitizeFilename(filename);
  if (!safeFilename) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const formatIndex = ALLOWED_FORMATS.indexOf(format);
  if (formatIndex === -1) {
    return res.status(400).json({ error: 'Invalid format' });
  }
  // Use sanitized/allowlisted values to avoid passing tainted data to the command
  const safeFormat = ALLOWED_FORMATS[formatIndex];
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

router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files must be a non-empty array' });
  }
  // Sanitize each filename to produce new untainted values
  const safeFiles = [];
  for (const f of files) {
    const safe = sanitizeFilename(f);
    if (!safe) {
      return res.status(400).json({ error: 'Invalid filename(s) detected' });
    }
    safeFiles.push(safe);
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...safeFiles]);
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
