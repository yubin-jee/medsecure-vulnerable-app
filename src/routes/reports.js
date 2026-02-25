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

// FIXED: Server-Side Request Forgery (CWE-918) - validate URL against allowlist
const https = require('https');

// Map of allowed host keys to their base URLs
const ALLOWED_HOST_URLS = {
  'api': 'https://api.example.com',
  'reports': 'https://reports.example.com',
  'data': 'https://data.example.com',
};

router.get('/fetch-external', (req, res) => {
  const hostKey = req.query.host;
  const resourcePath = req.query.path;

  if (!hostKey || typeof hostKey !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid host parameter' });
  }

  // Look up the base URL from the allowlist using the host key
  const baseUrl = ALLOWED_HOST_URLS[hostKey];
  if (!baseUrl) {
    return res.status(403).json({ error: 'Requested host is not in the allowed list' });
  }

  // Construct the safe URL from trusted base URL and validated path
  let safeUrl = baseUrl;
  if (resourcePath && typeof resourcePath === 'string') {
    // Sanitize path: remove path traversal sequences and ensure it starts with /
    const sanitizedPath = '/' + resourcePath.replace(/\.\./g, '').replace(/^\/+/, '');
    safeUrl = baseUrl + sanitizedPath;
  }

  https.get(safeUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
