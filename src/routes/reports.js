const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Helper: returns a safe report type from a constant string, or null if invalid.
// Switch with literal return values breaks CodeQL taint flow from user input.
function getSafeReportType(input) {
  switch (input) {
    case 'summary': return 'summary';
    case 'detailed': return 'detailed';
    case 'audit': return 'audit';
    case 'compliance': return 'compliance';
    case 'financial': return 'financial';
    default: return null;
  }
}

// Helper: returns a safe export format from a constant string, or null if invalid.
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

// Helper: returns a safe filename via path.basename and strict regex, or null if invalid.
const SAFE_FILENAME_RE = /^[a-zA-Z0-9._-]+$/;
function getSafeFilename(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return null;
  }
  const basename = path.basename(input);
  if (!SAFE_FILENAME_RE.test(basename)) {
    return null;
  }
  return basename;
}

// FIXED: Command injection (CWE-78) - allowlist via switch and execFileSync with argument array
router.get('/generate', (req, res) => {
  const reportType = getSafeReportType(req.query.type);
  if (!reportType) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - allowlist/regex validation and execFile with argument array
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = getSafeFilename(filename);
  if (!safeFilename) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const safeFormat = getSafeExportFormat(format);
  if (!safeFormat) {
    return res.status(400).json({ error: 'Invalid export format' });
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

// FIXED: Command injection via filename (CWE-78) - validate filenames, execFileSync with argument array and '--' separator
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files array is required' });
  }
  const safeFiles = [];
  for (const f of files) {
    const safeName = getSafeFilename(f);
    if (!safeName) {
      return res.status(400).json({ error: 'One or more filenames are invalid' });
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
