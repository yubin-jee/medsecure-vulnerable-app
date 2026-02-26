const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Returns a safe report type string literal if the input matches an allowed value,
 * or null otherwise. Using switch/case with string literal returns ensures the
 * returned value has no data-flow dependency on the user input.
 */
function getSafeReportType(input) {
  switch (input) {
    case 'summary': return 'summary';
    case 'detailed': return 'detailed';
    case 'audit': return 'audit';
    case 'compliance': return 'compliance';
    case 'patient': return 'patient';
    case 'financial': return 'financial';
    default: return null;
  }
}

/**
 * Returns a safe export format string literal if the input matches an allowed value,
 * or null otherwise.
 */
function getSafeExportFormat(input) {
  switch (input) {
    case 'csv': return 'csv';
    case 'json': return 'json';
    case 'xml': return 'xml';
    case 'pdf': return 'pdf';
    case 'xlsx': return 'xlsx';
    default: return null;
  }
}

/**
 * Validates and sanitizes a filename. Returns the sanitized basename if it
 * contains only safe characters, or null if the input is invalid.
 */
function sanitizeFilename(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 255) {
    return null;
  }
  const base = path.basename(input);
  if (base.length === 0 || base === '.' || base === '..') {
    return null;
  }
  if (!/^[a-zA-Z0-9_][a-zA-Z0-9_.\-]*$/.test(base)) {
    return null;
  }
  return base;
}

// FIX (CodeQL alert #19): Use execFileSync with switch-validated input (CWE-78)
router.get('/generate', (req, res) => {
  const safeType = getSafeReportType(req.query.type);
  if (safeType === null) {
    return res.status(400).json({ error: 'Invalid report type. Allowed: summary, detailed, audit, compliance, patient, financial' });
  }
  const output = execFileSync('generate-report', ['--type', safeType, '--format', 'pdf']);
  res.send(output);
});

// FIX (CodeQL alert #20): Use execFile with switch-validated format and sanitized filename (CWE-78)
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = sanitizeFilename(filename);
  if (safeFilename === null) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
  }
  const safeFormat = getSafeExportFormat(format);
  if (safeFormat === null) {
    return res.status(400).json({ error: 'Invalid format. Allowed: csv, json, xml, pdf, xlsx' });
  }
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

// FIX (CodeQL alert #21): Use execFileSync with sanitized filenames and -- separator (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files must be a non-empty array' });
  }
  const safeFiles = [];
  for (const file of files) {
    const safeName = sanitizeFilename(file);
    if (safeName === null) {
      return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
    }
    safeFiles.push(safeName);
  }
  // Use -- to prevent option injection via filenames starting with -
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
