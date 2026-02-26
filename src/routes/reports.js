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

// FIX: Server-Side Request Forgery (CWE-918) - allowlist-based host lookup
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Map of allowed host keys to their trusted base URLs
const ALLOWED_HOSTS = {
  'api': 'https://api.example.com',
  'data': 'https://data.example.com',
  'reports': 'https://reports.example.com',
};

router.get('/fetch-external', (req, res) => {
  const hostKey = req.query.host;
  const resourcePath = req.query.path;

  // Look up the base URL from the allowlist using a non-tainted key
  const baseUrl = ALLOWED_HOSTS[hostKey];
  if (!baseUrl) {
    return res.status(400).json({
      error: 'Invalid host. Allowed hosts: ' + Object.keys(ALLOWED_HOSTS).join(', ')
    });
  }

  // Sanitize the resource path to prevent path traversal
  if (resourcePath && (/\.\./.test(resourcePath) || resourcePath.includes('\0'))) {
    return res.status(400).json({ error: 'Invalid resource path.' });
  }

  // Construct URL entirely from trusted base + sanitized path
  const trustedUrl = new URL(baseUrl);
  if (resourcePath) {
    // Normalize and append the path safely
    trustedUrl.pathname = '/' + resourcePath.replace(/^\/+/, '');
  }

  const client = trustedUrl.protocol === 'https:' ? https : http;

  client.get(trustedUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource.' });
  });
});

module.exports = router;
