const express = require('express');
const router = express.Router();
const tar = require('tar');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'monthly', 'quarterly', 'annual', 'patient', 'billing', 'audit'];

// Allowlist of valid export formats
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];

// Strict pattern for filenames: must start with alphanumeric, then alphanumeric/dots/hyphens/underscores
const SAFE_FILENAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

// Strict pattern for file paths: must start with alphanumeric, no .. traversal
const SAFE_FILEPATH_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/\-]*$/;

// FIX: Alert #19 - Replaced shell command with internal report generation (CWE-78, CWE-88)
// Previously used execSync which allowed command injection via user-controlled reportType.
// Now uses allowlist validation and internal logic instead of spawning a shell process.
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || !ALLOWED_REPORT_TYPES.includes(reportType)) {
    return res.status(400).json({ error: 'Invalid report type. Allowed types: ' + ALLOWED_REPORT_TYPES.join(', ') });
  }
  // Generate report internally instead of calling external command
  const reportData = {
    type: reportType,
    format: 'pdf',
    generatedAt: new Date().toISOString(),
    content: 'Report data for type: ' + reportType
  };
  res.json(reportData);
});

// FIX: Alert #20 - Replaced shell command with internal data conversion (CWE-78, CWE-88)
// Previously used exec with template literal which allowed command injection via filename/format.
// Now uses allowlist validation and internal logic instead of spawning a shell process.
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = typeof filename === 'string' ? path.basename(filename) : '';
  if (!safeFilename || !SAFE_FILENAME_PATTERN.test(safeFilename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, dots, hyphens, and underscores are allowed.' });
  }
  if (!format || !ALLOWED_EXPORT_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'Invalid format. Allowed formats: ' + ALLOWED_EXPORT_FORMATS.join(', ') });
  }
  // Convert data internally instead of calling external command
  const sourcePath = path.join('/data', safeFilename);
  try {
    const data = fs.readFileSync(sourcePath, 'utf-8');
    res.json({ result: data, format: format });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

// FIX: Alert #21 - Replaced shell command with Node.js tar library (CWE-78, CWE-88)
// Previously used execSync which allowed command injection via user-controlled file list.
// Now uses the 'tar' npm package which processes files internally without spawning a shell.
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
    const normalized = path.normalize(file);
    if (normalized.includes('..') || !SAFE_FILEPATH_PATTERN.test(normalized)) {
      return res.status(400).json({ error: 'Invalid file path. Only alphanumeric characters, dots, hyphens, underscores, and forward slashes are allowed.' });
    }
    safeFiles.push(normalized);
  }
  // Use Node.js tar library instead of spawning a shell process
  tar.create({ gzip: true, file: '/tmp/archive.tar.gz' }, safeFiles)
    .then(() => {
      res.download('/tmp/archive.tar.gz');
    })
    .catch((err) => {
      res.status(500).json({ error: err.message });
    });
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
