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

const ALLOWED_HOSTS = [
  'api.medsecure.com',
  'data.medsecure.com',
  'reports.medsecure.com'
];

router.get('/fetch-external', (req, res) => {
  const urlInput = req.query.url;

  if (!urlInput) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(urlInput);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Only allow http protocol
  if (parsedUrl.protocol !== 'http:') {
    return res.status(400).json({ error: 'Only HTTP protocol is allowed' });
  }

  // Validate hostname against allowlist
  if (!ALLOWED_HOSTS.includes(parsedUrl.hostname)) {
    return res.status(403).json({ error: 'Requested host is not allowed' });
  }

  // Use options object with hostname from allowlist to prevent SSRF
  const safeHost = ALLOWED_HOSTS.find(h => h === parsedUrl.hostname);
  const requestOptions = {
    hostname: safeHost,
    port: 80,
    path: parsedUrl.pathname + parsedUrl.search
  };
  http.get(requestOptions, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
