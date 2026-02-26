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

// FIX: Server-Side Request Forgery (CWE-918) - reconstruct URL from trusted components
const http = require('http');
const https = require('https');

const ALLOWED_EXTERNAL_HOSTS = {
  'api': 'https://api.medsecure.example.com',
  'data': 'https://data.medsecure.example.com',
  'reports': 'https://reports.medsecure.example.com'
};

router.get('/fetch-external', (req, res) => {
  const hostKey = req.query.host;
  const resourcePath = req.query.path;

  if (!hostKey || typeof hostKey !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid host parameter' });
  }

  // Pick the base URL from the allowlist — no user input in the hostname
  const baseUrl = ALLOWED_EXTERNAL_HOSTS[hostKey];
  if (!baseUrl) {
    return res.status(403).json({ error: 'Requested host is not in the allowed list' });
  }

  // Build the full URL from trusted base + optional path
  let targetUrl;
  try {
    targetUrl = new URL(baseUrl);
    if (resourcePath && typeof resourcePath === 'string') {
      // Normalize the path to prevent path traversal (e.g. "../../")
      const normalizedPath = path.posix.normalize('/' + resourcePath);
      targetUrl.pathname = normalizedPath;
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid request parameters' });
  }

  const client = targetUrl.protocol === 'https:' ? https : http;
  client.get(targetUrl.href, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
