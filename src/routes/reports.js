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

// FIX: Server-Side Request Forgery (CWE-918) - validate URL against allowlist
const http = require('http');
const https = require('https');
const ALLOWED_HOSTS = [
  'api.medsecure.example.com',
  'reports.medsecure.example.com',
  'data.medsecure.example.com',
];
router.get('/fetch-external', (req, res) => {
  const rawUrl = req.query.url;
  if (!rawUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Only allow http and https protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only http and https protocols are allowed' });
  }

  // Validate hostname against allowlist
  if (!ALLOWED_HOSTS.includes(parsedUrl.hostname)) {
    return res.status(403).json({ error: 'Requested host is not in the allowlist' });
  }

  // Prevent path traversal in URL path
  const normalizedPath = path.normalize(parsedUrl.pathname);
  if (normalizedPath.includes('..')) {
    return res.status(400).json({ error: 'Path traversal is not allowed' });
  }

  const client = parsedUrl.protocol === 'https:' ? https : http;
  client.get(parsedUrl.href, (response) => {
    // Do not follow redirects to non-allowlisted hosts
    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
      let redirectUrl;
      try {
        redirectUrl = new URL(response.headers.location);
      } catch (e) {
        return res.status(502).json({ error: 'Invalid redirect URL from upstream' });
      }
      if (!ALLOWED_HOSTS.includes(redirectUrl.hostname)) {
        return res.status(403).json({ error: 'Redirect target is not in the allowlist' });
      }
    }
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
