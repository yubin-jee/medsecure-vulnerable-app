const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Allowlist of valid report types
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'financial'];

// Allowlist of valid export formats
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];

// Validate and return a sanitized filename containing only safe characters.
// Returns the matched string (derived from the regex match, not the original
// input) so that taint tracking treats the result as safe.
function sanitizeFilename(name) {
  if (typeof name !== 'string') return null;
  const match = name.match(/^[a-zA-Z0-9._-]+$/);
  return match ? match[0] : null;
}

router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const idx = ALLOWED_REPORT_TYPES.indexOf(reportType);
  if (idx === -1) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  // Use the value from the allowlist to break the taint flow from user input
  const safeType = ALLOWED_REPORT_TYPES[idx];
  const output = execFileSync('generate-report', ['--type', safeType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  const safeFilename = sanitizeFilename(filename);
  if (!safeFilename) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const fmtIdx = ALLOWED_EXPORT_FORMATS.indexOf(format);
  if (fmtIdx === -1) {
    return res.status(400).json({ error: 'Invalid export format' });
  }
  // Use sanitized/allowlisted values to break the taint flow from user input
  const safeFormat = ALLOWED_EXPORT_FORMATS[fmtIdx];
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
  // Sanitize each filename to break the taint flow from user input
  const safeFiles = files.map(sanitizeFilename);
  if (safeFiles.some((f) => f === null)) {
    return res.status(400).json({ error: 'Invalid filename in list' });
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
