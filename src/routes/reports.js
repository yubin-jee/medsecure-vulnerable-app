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

// FIXED: Server-Side Request Forgery (CWE-918) - use allowlist-based URL construction
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Map of allowed report source keys to their base URLs.
// The user selects a source by key; the hostname is never taken from user input.
const ALLOWED_REPORT_SOURCES = {
  'api': 'https://api.medsecure.example.com',
  'data': 'https://data.medsecure.example.com',
  'reports': 'https://reports.medsecure.example.com'
};

// Sanitize the path component to prevent path traversal
function sanitizePath(userPath) {
  if (!userPath) {
    return '/';
  }
  // Normalize and resolve the path to prevent traversal (e.g. /../)
  const normalized = path.posix.normalize(userPath);
  // Ensure it starts with /
  return normalized.startsWith('/') ? normalized : '/' + normalized;
}

router.get('/fetch-external', (req, res) => {
  const source = req.query.source;
  const resourcePath = req.query.path;

  if (!source) {
    return res.status(400).json({ error: 'Missing source parameter. Valid sources: ' + Object.keys(ALLOWED_REPORT_SOURCES).join(', ') });
  }

  // Look up the base URL from the allowlist using the user-provided key.
  // This ensures the hostname is never derived from user input.
  const baseUrl = ALLOWED_REPORT_SOURCES[source];
  if (!baseUrl) {
    return res.status(403).json({ error: 'Invalid source. Valid sources: ' + Object.keys(ALLOWED_REPORT_SOURCES).join(', ') });
  }

  // Construct the full URL from the trusted base URL and a sanitized path
  const safePath = sanitizePath(resourcePath);
  const targetUrl = baseUrl + safePath;

  const client = targetUrl.startsWith('https:') ? https : http;
  client.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
