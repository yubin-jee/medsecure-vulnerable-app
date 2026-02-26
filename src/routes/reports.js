const express = require('express');
const router = express.Router();
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// VULN: Command injection (CWE-78) - user input in shell command
router.get('/generate', (req, res) => {
  const reportType = req.query.type;
  const output = execSync('generate-report --type ' + reportType + ' --format pdf');
  res.send(output);
});

// VULN: Command injection (CWE-78) - template literal in exec
router.post('/export', (req, res) => {
  const { filename, format } = req.body;
  exec(`convert-data "${filename}" --output-format ${format}`, (err, stdout) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// FIX: Path traversal (CWE-22) - sanitize filename and use root option to prevent directory traversal
router.get('/download', (req, res) => {
  const filename = path.basename(req.query.file);
  res.sendFile(filename, { root: '/reports' });
});

// FIX: Path traversal (CWE-22) - validate and sanitize path to prevent directory traversal
router.get('/view', (req, res) => {
  const userPath = req.query.path;
  if (typeof userPath !== 'string' || !userPath) {
    return res.status(400).json({ error: 'Missing path parameter' });
  }
  // Strip directory components to get only the filename
  const reportName = path.basename(userPath);
  // Reject any remaining path traversal patterns
  if (reportName.indexOf('..') !== -1 || reportName.indexOf('/') !== -1 || reportName.indexOf('\\') !== -1) {
    return res.status(400).json({ error: 'Invalid file path' });
  }
  const resolvedPath = path.join('/reports', reportName);
  const content = fs.readFileSync(resolvedPath, 'utf-8');
  res.json({ content });
});

// VULN: Command injection via filename (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  const fileList = files.join(' ');
  execSync(`tar -czf /tmp/archive.tar.gz ${fileList}`);
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
