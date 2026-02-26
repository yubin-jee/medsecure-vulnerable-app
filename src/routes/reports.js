const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  if (!reportType || typeof reportType !== 'string') {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  // Sanitize by removing any characters that are not alphanumeric, underscore, or hyphen
  const sanitizedType = reportType.replace(/[^a-zA-Z0-9_-]/g, '');
  if (sanitizedType.length === 0) {
    return res.status(400).json({ error: 'Invalid report type' });
  }
  const output = execFileSync('generate-report', ['--type', sanitizedType, '--format', 'pdf']);
  res.send(output);
});

router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  if (!format || typeof format !== 'string') {
    return res.status(400).json({ error: 'Invalid format' });
  }
  // Sanitize by stripping dangerous characters
  const sanitizedFilename = filename.replace(/[^a-zA-Z0-9_.\-\/]/g, '');
  const sanitizedFormat = format.replace(/[^a-zA-Z0-9_-]/g, '');
  if (sanitizedFilename.length === 0 || sanitizedFormat.length === 0) {
    return res.status(400).json({ error: 'Invalid filename or format' });
  }
  execFile('convert-data', [sanitizedFilename, '--output-format', sanitizedFormat], (err, stdout) => {
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
  // Sanitize each filename by stripping dangerous characters
  const sanitizedFiles = files.map(file => {
    if (typeof file !== 'string') {
      return '';
    }
    return file.replace(/[^a-zA-Z0-9_.\-\/]/g, '');
  });
  if (sanitizedFiles.some(f => f.length === 0)) {
    return res.status(400).json({ error: 'Invalid filename in list' });
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
