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

// FIX: Server-Side Request Forgery (CWE-918) - use allowlist of predefined URLs
const https = require('https');

// Allowlist mapping of permitted resource identifiers to their full, fixed URLs.
// No part of the outgoing request URL is derived from user input.
const ALLOWED_EXTERNAL_URLS = {
  'api-status':    'https://api.medsecure.example.com/status',
  'api-reports':   'https://api.medsecure.example.com/reports',
  'reports-latest': 'https://reports.medsecure.example.com/latest',
  'reports-summary': 'https://reports.medsecure.example.com/summary',
  'data-export':   'https://data.medsecure.example.com/export',
  'data-metrics':  'https://data.medsecure.example.com/metrics',
};

router.get('/fetch-external', (req, res) => {
  const resourceKey = req.query.resource;

  if (!resourceKey || typeof resourceKey !== 'string') {
    return res.status(400).json({
      error: 'Missing or invalid resource parameter.',
      allowed: Object.keys(ALLOWED_EXTERNAL_URLS),
    });
  }

  // Look up the full URL from the allowlist — no user input is used in the URL
  const targetUrl = ALLOWED_EXTERNAL_URLS[resourceKey];
  if (!targetUrl) {
    return res.status(403).json({
      error: 'Requested resource is not in the allowed list.',
      allowed: Object.keys(ALLOWED_EXTERNAL_URLS),
    });
  }

  https.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
