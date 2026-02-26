const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Only allow alphanumeric characters, hyphens, and underscores in command arguments
const SAFE_ARG_PATTERN = /^[a-zA-Z0-9._-]+$/;

function validateArg(value) {
  if (typeof value !== 'string' || !SAFE_ARG_PATTERN.test(value)) {
    return null;
  }
  return value;
}

router.get('/generate', (req, res) => {
  const reportType = validateArg(req.query.type);
  if (!reportType) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const filename = validateArg(req.body.filename);
  const format = validateArg(req.body.format);
  if (!filename || !format) {
    return res.status(400).json({ error: 'Invalid filename or format' });
  }
  execFile('convert-data', [filename, '--output-format', format], (err, stdout) => {
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
    return res.status(400).json({ error: 'Invalid files list' });
  }
  const sanitizedFiles = [];
  for (const file of files) {
    const validated = validateArg(file);
    if (!validated) {
      return res.status(400).json({ error: 'Invalid filename: ' + String(file) });
    }
    sanitizedFiles.push(validated);
  }
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...sanitizedFiles]);
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
