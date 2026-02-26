const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - use execFileSync with argument array and allowlist validation
function getSafeReportType(input) {
  switch (input) {
    case 'pdf': return 'pdf';
    case 'csv': return 'csv';
    case 'html': return 'html';
    case 'json': return 'json';
    case 'xml': return 'xml';
    default: return null;
  }
}
router.get('/generate', (req, res) => {
  const safeReportType = getSafeReportType(req.query.type);
  if (safeReportType === null) {
    return res.status(400).json({ error: 'Invalid report type. Allowed: pdf, csv, html, json, xml' });
  }
  const output = execFileSync('generate-report', ['--type', safeReportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - use execFile with argument array and strict validation
function getSafeExportFormat(input) {
  switch (input) {
    case 'pdf': return 'pdf';
    case 'csv': return 'csv';
    case 'html': return 'html';
    case 'json': return 'json';
    case 'xml': return 'xml';
    default: return null;
  }
}
function sanitizeFilename(input) {
  if (typeof input !== 'string' || input.length === 0) return null;
  // Strip any characters that are not alphanumeric, underscores, hyphens, or dots
  const sanitized = input.replace(/[^a-zA-Z0-9_.\-]/g, '');
  if (sanitized.length === 0 || sanitized !== input) return null;
  return sanitized;
}
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = sanitizeFilename(filename);
  if (safeFilename === null) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
  }
  const safeFormat = getSafeExportFormat(format);
  if (safeFormat === null) {
    return res.status(400).json({ error: 'Invalid format. Allowed: pdf, csv, html, json, xml' });
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

// FIXED: Command injection via filename (CWE-78) - use execFileSync with argument array and strict validation
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files must be a non-empty array' });
  }
  // Validate and sanitize each filename to break taint chain
  const safeFiles = [];
  for (const file of files) {
    const safeName = sanitizeFilename(file);
    if (safeName === null) {
      return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots are allowed.' });
    }
    safeFiles.push(safeName);
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
