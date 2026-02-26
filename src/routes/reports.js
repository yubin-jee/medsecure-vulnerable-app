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
const { URL } = require('url');

const ALLOWED_EXTERNAL_HOSTS = [
  'api.example.com',
  'data.example.com',
  'reports.example.com'
];

function isAllowedUrl(inputUrl) {
  let parsed;
  try {
    parsed = new URL(inputUrl);
  } catch (e) {
    return false;
  }

  // Only allow http and https protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }

  // Reject URLs with credentials
  if (parsed.username || parsed.password) {
    return false;
  }

  // Validate hostname against allowlist
  if (!ALLOWED_EXTERNAL_HOSTS.includes(parsed.hostname)) {
    return false;
  }

  return true;
}

router.get('/fetch-external', (req, res) => {
  const url = req.query.url;

  if (!url || !isAllowedUrl(url)) {
    return res.status(400).json({ error: 'Invalid or disallowed URL. Only approved external hosts are permitted.' });
  }

  const parsed = new URL(url);
  const client = parsed.protocol === 'https:' ? https : http;

  client.get(parsed, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource.' });
  });
});

module.exports = router;
