const express = require('express');
const router = express.Router();
const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// FIXED: Command injection (CWE-78) - use execFileSync with argument array to prevent shell injection
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIXED: Command injection (CWE-78) - use execFile with argument array to prevent shell injection
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
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

// FIXED: Command injection via filename (CWE-78) - use execFileSync with argument array to prevent shell injection
router.post('/compress', (req, res) => {
  const { files } = req.body;
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...files]);
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
