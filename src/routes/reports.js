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

// FIX: Command injection (CWE-78) - use execFileSync with argument array instead of shell interpolation
router.post('/compress', (req, res) => {
  const { files } = req.body;

  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files must be a non-empty array' });
  }

  // Validate each filename to reject path traversal and shell metacharacters
  const safeNamePattern = /^[a-zA-Z0-9._-]+$/;
  for (const file of files) {
    if (typeof file !== 'string' || !safeNamePattern.test(file)) {
      return res.status(400).json({ error: 'Invalid filename: ' + String(file) });
    }
  }

  // Use execFileSync which does not spawn a shell, passing arguments as an array
  const { execFileSync } = require('child_process');
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...files]);
  res.download('/tmp/archive.tar.gz');
});

// FIX: Server-Side Request Forgery (CWE-918) - use allowlisted URLs only
const https = require('https');

// Map of allowed source keys to their full URLs. No user input is used in the request URL.
const ALLOWED_EXTERNAL_URLS = {
  'patient-records': 'https://api.medsecure.example.com/patient-records',
  'lab-results': 'https://data.medsecure.example.com/lab-results',
  'billing-summary': 'https://reports.medsecure.example.com/billing-summary',
};

router.get('/fetch-external', (req, res) => {
  const source = req.query.source;

  if (!source || typeof source !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid source parameter' });
  }

  // Look up the fully-qualified URL from the allowlist; user input selects a key, not a URL
  const targetUrl = ALLOWED_EXTERNAL_URLS[source];
  if (!targetUrl) {
    return res.status(403).json({
      error: 'Unknown source. Allowed sources: ' + Object.keys(ALLOWED_EXTERNAL_URLS).join(', ')
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
