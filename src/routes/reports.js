const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - inline allowlist regex + execFileSync with argument array
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  // Only allow known safe report types (CodeQL-recognized match() sanitizer)
  if (!reportType || !reportType.match(/^(summary|detailed|audit|compliance|financial)$/)) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - inline regex validation + execFile with argument array
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  // Only allow safe characters in filename (CodeQL-recognized match() sanitizer)
  if (!filename || !filename.match(/^[\w.\-]+$/)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  // Only allow known safe export formats
  if (!format || !format.match(/^(csv|json|xml|pdf|xlsx)$/)) {
    return res.status(400).json({ error: 'Invalid export format' });
  }
  execFile('convert-data', ['--', filename, '--output-format', format], (err, stdout) => {
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

// FIXED: Command injection via filename (CWE-78) - inline regex validation + execFileSync with argument array + '--' separator
router.post('/compress', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'Files array is required' });
  }
  for (const f of files) {
    // Only allow safe characters in each filename (CodeQL-recognized match() sanitizer)
    if (typeof f !== 'string' || !f.match(/^[\w.\-]+$/)) {
      return res.status(400).json({ error: 'One or more filenames are invalid' });
    }
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', '--', ...files]);
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
