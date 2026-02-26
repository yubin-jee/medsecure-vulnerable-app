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

// FIXED: Server-Side Request Forgery (CWE-918) - use allowlist lookup instead of user-controlled URL
const https = require('https');

// Map of allowed report source keys to their trusted URLs.
// User input is only used as a lookup key, never as part of the URL itself,
// which completely eliminates the SSRF taint vector.
const ALLOWED_REPORT_SOURCES = {
  'api': 'https://api.example.com/data',
  'data': 'https://data.example.com/data',
  'reports': 'https://reports.example.com/data',
};

router.get('/fetch-external', (req, res) => {
  const source = req.query.source;

  if (!source || typeof source !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid source parameter' });
  }

  // Look up the URL from the allowlist using the source key.
  // The URL passed to https.get() is entirely from the trusted map — no user input in the URL.
  const targetUrl = ALLOWED_REPORT_SOURCES[source];
  if (!targetUrl) {
    return res.status(403).json({
      error: 'Unknown report source. Allowed sources: ' + Object.keys(ALLOWED_REPORT_SOURCES).join(', ')
    });
  }

  https.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch external resource' });
  });
});

module.exports = router;
