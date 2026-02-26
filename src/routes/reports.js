const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIX: Use execFileSync with allowlist lookup to prevent command injection (CWE-78)
const ALLOWED_REPORT_TYPES = ['summary', 'detailed', 'audit', 'compliance', 'patient', 'financial'];
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const typeIndex = ALLOWED_REPORT_TYPES.indexOf(reportType);
  if (typeIndex === -1) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  // Use the value from the constant array to break taint flow
  const safeType = ALLOWED_REPORT_TYPES[typeIndex];
  const output = execFileSync('generate-report', ['--type', safeType, '--format', 'pdf']);
  res.send(output);
});

// FIX: Use execFile with allowlist and path.basename to prevent command injection (CWE-78)
const ALLOWED_EXPORT_FORMATS = ['csv', 'json', 'xml', 'pdf', 'xlsx'];
const SAFE_FILENAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_.\-]*$/;
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  // Sanitize filename using path.basename to strip directory components
  const safeFilename = path.basename(filename || '');
  if (!safeFilename || !SAFE_FILENAME_RE.test(safeFilename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const formatIndex = ALLOWED_EXPORT_FORMATS.indexOf(format);
  if (formatIndex === -1) {
    return res.status(400).json({ error: 'Invalid format' });
  }
  // Use the value from the constant array to break taint flow
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

// FIX: Use execFileSync with path.basename sanitization to prevent command injection (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files must be a non-empty array' });
  }
  // Sanitize each filename using path.basename to strip directory components
  const safeFiles = files.map((file) => {
    if (typeof file !== 'string') {
      return null;
    }
    const baseName = path.basename(file);
    if (!baseName || !SAFE_FILENAME_RE.test(baseName)) {
      return null;
    }
    return baseName;
  });
  if (safeFiles.some((f) => f === null)) {
    return res.status(400).json({ error: 'Invalid filename in files list' });
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
