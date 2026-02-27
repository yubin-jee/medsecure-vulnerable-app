const express = require('express');
const router = express.Router();
const { execSync, exec, execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

// Rate limiter for routes that execute system commands or access the filesystem
const commandRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// FIX: Use execFileSync to avoid shell command injection (CWE-78)
// Rate-limited to prevent abuse of system command execution
router.get('/generate', commandRateLimiter, (req, res) => {
  const reportType = req.query.type;
  const output = execFileSync('generate-report', ['--type', reportType, '--format', 'pdf']);
  res.send(output);
});

// FIX: Use execFile to avoid shell command injection (CWE-78)
// Rate-limited to prevent abuse of system command execution
router.post('/export', commandRateLimiter, (req, res) => {
  const { filename, format } = req.body;
  execFile('convert-data', [filename, '--output-format', format], (err, stdout) => {
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

// FIX: Use execFileSync with array arguments to avoid shell command injection (CWE-78)
// Rate-limited to prevent abuse of system command execution and filesystem access
router.post('/compress', commandRateLimiter, (req, res) => {
  const { files } = req.body;
  execFileSync('tar', ['-czf', '/tmp/archive.tar.gz', ...files]);
  res.download('/tmp/archive.tar.gz');
});

// VULN: Server-Side Request Forgery (CWE-918)
const http = require('http');
router.get('/fetch-external', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json({ data }));
  });
});

module.exports = router;
