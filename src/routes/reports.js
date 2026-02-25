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

// FIX: Server-Side Request Forgery (CWE-918) - use allowlisted resource map
// instead of passing user-controlled URLs to http.get
const http = require('http');
const https = require('https');

// Map of allowed resource keys to their full URLs.
// No user input flows into the URL — the user selects a key, and the
// corresponding constant URL is fetched.
const ALLOWED_RESOURCES = {
  'api-data': 'https://api.example.com/data',
  'reports-summary': 'https://reports.example.com/summary',
  'data-stats': 'https://data.example.com/stats'
};

router.get('/fetch-external', (req, res) => {
  const resourceKey = req.query.resource;
  if (!resourceKey) {
    return res.status(400).json({
      error: 'Resource parameter is required',
      allowed: Object.keys(ALLOWED_RESOURCES)
    });
  }

  // Only allow keys that exist in the constant map (prevents SSRF)
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_RESOURCES, resourceKey)) {
    return res.status(403).json({
      error: 'Unknown resource key',
      allowed: Object.keys(ALLOWED_RESOURCES)
    });
  }

  // URL comes entirely from the constant map — no user input in the URL
  const targetUrl = ALLOWED_RESOURCES[resourceKey];
  const parsedUrl = new URL(targetUrl);
  const client = parsedUrl.protocol === 'https:' ? https : http;

  client.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
