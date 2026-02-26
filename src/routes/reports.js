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

// FIXED: Server-Side Request Forgery (CWE-918) - use predefined URL map instead of user-supplied URLs
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Map of allowed source identifiers to their predefined URLs.
// User input selects a key; the actual URL is never derived from user input.
const ALLOWED_REPORT_SOURCES = {
  'api-data': 'https://api.example.com/data',
  'external-reports': 'https://reports.example.com/latest',
  'data-feed': 'https://data.example.com/feed'
};

router.get('/fetch-external', (req, res) => {
  const source = req.query.source;

  if (!source || !Object.prototype.hasOwnProperty.call(ALLOWED_REPORT_SOURCES, source)) {
    return res.status(400).json({
      error: 'Invalid source. Allowed sources: ' + Object.keys(ALLOWED_REPORT_SOURCES).join(', ')
    });
  }

  // URL is entirely server-defined; no user input flows into the request URL
  const targetUrl = ALLOWED_REPORT_SOURCES[source];
  const parsed = new URL(targetUrl);
  const client = parsed.protocol === 'https:' ? https : http;

  client.get(targetUrl, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  }).on('error', (err) => {
    res.status(502).json({ error: 'Failed to fetch external resource.' });
  });
});

module.exports = router;
