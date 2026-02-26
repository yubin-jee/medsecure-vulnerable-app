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

// FIX: Server-Side Request Forgery (CWE-918) - use allowlist lookup to prevent SSRF
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Map of allowed external host identifiers to their base URLs.
// User input is only used as a lookup key; the actual URL fetched comes
// entirely from these constant values, breaking the taint chain.
const ALLOWED_EXTERNAL_URLS = {
  'api.example.com': 'https://api.example.com',
  'data.example.com': 'https://data.example.com',
  'reports.example.com': 'https://reports.example.com',
};

router.get('/fetch-external', (req, res) => {
  const userUrl = req.query.url;

  if (!userUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(userUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Only allow http and https protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only http and https protocols are allowed' });
  }

  // Look up the base URL from our allowlist using the hostname as key.
  // The returned value is a constant string from the map, not derived from user input.
  const baseUrl = ALLOWED_EXTERNAL_URLS[parsedUrl.hostname];
  if (!baseUrl) {
    return res.status(403).json({ error: 'Requested host is not in the allowed list' });
  }

  // Use only the constant base URL from the allowlist for the outbound request
  const client = baseUrl.startsWith('https') ? https : http;
  client.get(baseUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
