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
const http = require('http');
const https = require('https');

const ALLOWED_EXTERNAL_HOSTS = [
  'api.medsecure.example.com',
  'reports.medsecure.example.com',
  'data.medsecure.example.com',
];

router.get('/fetch-external', (req, res) => {
  const urlInput = req.query.url;

  if (!urlInput || typeof urlInput !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid url parameter' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(urlInput);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Only allow http and https protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only http and https protocols are allowed' });
  }

  // Reject URLs containing user credentials to prevent credential smuggling
  if (parsedUrl.username || parsedUrl.password) {
    return res.status(400).json({ error: 'URLs with embedded credentials are not allowed' });
  }

  // Pick protocol literal based on validated value (breaks taint chain)
  const useHttps = parsedUrl.protocol === 'https:';

  // Validate hostname against allowlist to prevent SSRF
  // Use the allowlisted value (not the user-provided value) to construct the request URL
  const allowedHost = ALLOWED_EXTERNAL_HOSTS.find(
    (host) => host === parsedUrl.hostname
  );
  if (!allowedHost) {
    return res.status(403).json({ error: 'Requested host is not in the allowed list' });
  }

  // Construct a safe URL using only non-tainted allowlisted values and a fixed path
  // The hostname comes from the allowlist constant, and protocol from a literal string
  const safeUrl = (useHttps ? 'https' : 'http') + '://' + allowedHost + '/data';

  const client = useHttps ? https : http;
  client.get(safeUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
