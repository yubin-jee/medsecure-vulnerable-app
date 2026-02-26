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

// VULN: Command injection via filename (CWE-78)
router.post('/compress', (req, res) => {
  const { files } = req.body;
  const fileList = files.join(' ');
  execSync(`tar -czf /tmp/archive.tar.gz ${fileList}`);
  res.download('/tmp/archive.tar.gz');
});

// FIX: Server-Side Request Forgery (CWE-918) - use allowlist lookup instead of user-provided URL
const http = require('http');

// Map of allowed endpoint keys to their base URLs.
// User input selects a key; the actual URL comes from this constant map.
const ALLOWED_ENDPOINTS = {
  'api': 'http://api.medsecure.example.com',
  'reports': 'http://reports.medsecure.example.com',
  'data': 'http://data.medsecure.example.com',
};

router.get('/fetch-external', (req, res) => {
  const endpointKey = req.query.endpoint;

  if (!endpointKey) {
    return res.status(400).json({ error: 'endpoint parameter is required' });
  }

  // Look up the target URL from the allowlist; user input only selects the key,
  // not the URL itself, preventing SSRF.
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_ENDPOINTS, endpointKey)) {
    return res.status(403).json({ error: 'Requested endpoint is not in the allowlist' });
  }
  const targetUrl = ALLOWED_ENDPOINTS[endpointKey];

  http.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
