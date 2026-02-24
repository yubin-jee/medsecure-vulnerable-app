const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Frozen allowlist maps - values returned from these maps are trusted, not user-controlled
const ALLOWED_REPORT_TYPES = Object.freeze({
  'summary': 'summary',
  'detailed': 'detailed',
  'monthly': 'monthly',
  'quarterly': 'quarterly',
  'annual': 'annual',
  'patient': 'patient',
  'billing': 'billing',
  'audit': 'audit'
});

const ALLOWED_EXPORT_FORMATS = Object.freeze({
  'csv': 'csv',
  'json': 'json',
  'xml': 'xml',
  'pdf': 'pdf',
  'xlsx': 'xlsx'
});

// Strict pattern for filenames: must start with alphanumeric, then alphanumeric/dots/hyphens/underscores
const SAFE_FILENAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

// Strict pattern for file paths: must start with alphanumeric, no .. traversal
const SAFE_FILEPATH_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/\-]*$/;

// FIX: Alert #19 - Use execFileSync with args array + allowlist map lookup (CWE-78, CWE-88)
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  // Look up from frozen allowlist map; returned value is a trusted string literal, not user input
  const safeType = ALLOWED_REPORT_TYPES[reportType];
  if (!safeType) {
    return res.status(400).json({ error: 'Invalid report type. Allowed types: ' + Object.keys(ALLOWED_REPORT_TYPES).join(', ') });
  }
  const output = execFileSync('generate-report', ['--type', safeType, '--format', 'pdf']);
  res.send(output);
});

// FIX: Alert #20 - Use execFile with args array + input validation (CWE-78, CWE-88)
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  // Extract only the base filename to prevent path injection, then validate
  const safeFilename = typeof filename === 'string' ? path.basename(filename) : '';
  if (!safeFilename || !SAFE_FILENAME_PATTERN.test(safeFilename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, dots, hyphens, and underscores are allowed.' });
  }
  // Look up from frozen allowlist map; returned value is a trusted string literal, not user input
  const safeFormat = ALLOWED_EXPORT_FORMATS[format];
  if (!safeFormat) {
    return res.status(400).json({ error: 'Invalid format. Allowed formats: ' + Object.keys(ALLOWED_EXPORT_FORMATS).join(', ') });
  }
  execFile('convert-data', ['--', safeFilename, '--output-format', safeFormat], (err, stdout) => {
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

// FIX: Alert #21 - Use execFileSync with args array + input validation (CWE-78, CWE-88)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files must be a non-empty array.' });
  }
  // Validate and sanitize each file path individually
  const safeFiles = [];
  for (const file of files) {
    if (typeof file !== 'string') {
      return res.status(400).json({ error: 'Each file must be a string.' });
    }
    // Normalize and validate: reject traversal, must match safe pattern
    const normalized = path.normalize(file);
    if (normalized.includes('..') || !SAFE_FILEPATH_PATTERN.test(normalized)) {
      return res.status(400).json({ error: 'Invalid file path. Only alphanumeric characters, dots, hyphens, underscores, and forward slashes are allowed.' });
    }
    safeFiles.push(normalized);
  }
  // Use -- to separate tar options from file arguments to prevent argument injection
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
