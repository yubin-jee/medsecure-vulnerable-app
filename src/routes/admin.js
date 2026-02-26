const express = require('express');
const router = express.Router();
const db = require('../utils/database');

// VULN: Reflected XSS (CWE-79) - user input rendered without escaping
router.get('/search-users', (req, res) => {
  const query = req.query.q;
  res.send(`
    <html>
      <body>
        <h1>Search Results for: ${query}</h1>
        <div id="results"></div>
      </body>
    </html>
  `);
});

// VULN: Stored XSS (CWE-79) - rendering unsanitized DB content
router.get('/announcements', (req, res) => {
  const announcements = db.prepare('SELECT * FROM announcements').all();
  let html = '<html><body><h1>Announcements</h1>';
  announcements.forEach(a => {
    html += `<div class="announcement"><h2>${a.title}</h2><p>${a.body}</p></div>`;
  });
  html += '</body></html>';
  res.send(html);
});

// VULN: XSS in error page (CWE-79)
router.get('/settings', (req, res) => {
  const section = req.query.section;
  if (!['general', 'security', 'notifications'].includes(section)) {
    return res.send(`<html><body><h1>Error</h1><p>Invalid section: ${section}</p></body></html>`);
  }
  res.send(`<html><body><h1>Settings: ${section}</h1></body></html>`);
});

// VULN: Open redirect (CWE-601)
router.get('/redirect', (req, res) => {
  const returnUrl = req.query.url;
  res.redirect(returnUrl);
});

// VULN: XML External Entity injection risk (CWE-611)
const { parseString } = require('xml2js');
router.post('/import-config', (req, res) => {
  const xmlData = req.body.xml;
  parseString(xmlData, { explicitArray: false }, (err, result) => {
    if (err) return res.status(400).json({ error: 'Invalid XML' });
    res.json({ config: result });
  });
});

// Prototype pollution prevention: reject dangerous property names
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype', 'toString', 'valueOf', 'hasOwnProperty', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__']);

router.post('/update-settings', (req, res) => {
  const userSettings = req.body;
  const settings = Object.create(null);
  Object.keys(userSettings).forEach(key => {
    if (typeof key !== 'string' || FORBIDDEN_KEYS.has(key)) {
      return; // skip dangerous property names
    }
    settings[key] = userSettings[key];
  });
  res.json({ settings });
});

module.exports = router;
