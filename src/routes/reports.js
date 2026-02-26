const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'monthly', 'quarterly', 'annual'];

// Allowlist of valid export formats
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];

// Validates that a string contains only safe characters (alphanumeric, hyphens, underscores, dots)
function isSafeFilename(str) {
  return typeof str === 'string' && /^[a-zA-Z0-9._-]+$/.test(str);
}

router.get('/generate', (req, res) => {
  const reportTypeIndex = ALLOWED_REPORT_TYPES.indexOf(req.query.type);
  if (reportTypeIndex === -1) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const safeReportType = ALLOWED_REPORT_TYPES[reportTypeIndex];
  const output = execFileSync('generate-report', ['--type', safeReportType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!isSafeFilename(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const formatIndex = ALLOWED_EXPORT_FORMATS.indexOf(format);
  if (formatIndex === -1) {
    return res.status(400).json({ error: 'Invalid export format' });
  }
  // Use sanitized filename (strip to basename) and derive format from allowlist
  const safeFilename = path.basename(filename);
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

router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files must be a non-empty array' });
  }
  // Sanitize each filename: strip path components and validate characters
  const safeFiles = [];
  for (const file of files) {
    if (!isSafeFilename(file)) {
      return res.status(400).json({ error: 'Invalid filename in list' });
    }
    safeFiles.push(path.basename(String(file)));
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
