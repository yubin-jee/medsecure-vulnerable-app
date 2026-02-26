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

// FIX: Server-Side Request Forgery (CWE-918) - validate URL against allowed endpoints
const http = require('http');

// Map of allowed hostnames to their safe base URLs.
// User input is only used as a lookup key; the actual URL passed to http.get
// comes entirely from this server-side map, eliminating SSRF risk.
const ALLOWED_EXTERNAL_ENDPOINTS = new Map([
  ['api.example.com', 'http://api.example.com'],
  ['data.example.com', 'http://data.example.com'],
  ['reports.example.com', 'http://reports.example.com'],
]);

router.get('/fetch-external', (req, res) => {
  const rawUrl = req.query.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid url parameter' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Look up the target from the server-side allowlist using the hostname as key.
  // The URL value comes from the Map (not from user input), preventing SSRF.
  const safeBaseUrl = ALLOWED_EXTERNAL_ENDPOINTS.get(parsedUrl.hostname);
  if (!safeBaseUrl) {
    return res.status(403).json({ error: 'Requested host is not in the allowed list' });
  }

  http.get(safeBaseUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
