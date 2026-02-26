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

// FIX: Server-Side Request Forgery (CWE-918) - validate URL against allowlist of trusted hostnames
const http = require('http');
const https = require('https');

// Allowlist mapping of permitted host identifiers to their base URLs.
// The user supplies a host key and a path; the actual hostname is never taken from user input.
const ALLOWED_EXTERNAL_HOSTS = {
  'api': 'https://api.medsecure.example.com',
  'reports': 'https://reports.medsecure.example.com',
  'data': 'https://data.medsecure.example.com',
};

router.get('/fetch-external', (req, res) => {
  const hostKey = req.query.host;
  const resourcePath = req.query.path || '/';

  if (!hostKey || typeof hostKey !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid host parameter. Use one of: ' + Object.keys(ALLOWED_EXTERNAL_HOSTS).join(', ') });
  }

  // Look up the base URL from the allowlist — the hostname is never derived from user input
  const baseUrl = ALLOWED_EXTERNAL_HOSTS[hostKey];
  if (!baseUrl) {
    return res.status(403).json({ error: 'Requested host key is not in the allowed list. Use one of: ' + Object.keys(ALLOWED_EXTERNAL_HOSTS).join(', ') });
  }

  // Sanitize the path to prevent path traversal
  const sanitizedPath = resourcePath.replace(/\.\./g, '').replace(/\/\//g, '/');

  // Construct the full URL from trusted base + sanitized path (no user-controlled hostname)
  const targetUrl = new URL(sanitizedPath, baseUrl);
  const safeUrl = targetUrl.href;

  const client = targetUrl.protocol === 'https:' ? https : http;
  client.get(safeUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
