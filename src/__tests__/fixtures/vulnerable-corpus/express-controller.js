// Synthetic fixture for the vulnerable-corpus regression test suite.
// Every vulnerability here is deliberate. Do NOT import from this file.

const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const childProcess = require('child_process');

const app = express();

// TAINT001 — user input flowing into child_process.exec (command injection)
app.get('/cmd', (req, res) => {
  const cmd = req.query.cmd;
  childProcess.exec(cmd);
  res.send('ok');
});

// TAINT003 — path traversal
app.get('/file', (req, res) => {
  const filename = req.params.name;
  fs.readFile(filename, (err, data) => res.send(data));
});

// TAINT005 — open redirect
app.get('/login-callback', (req, res) => {
  res.redirect(req.query.next);
});

// TAINT007 — SSRF with provenance
app.get('/proxy', (req, res) => {
  const target = req.query.url;
  fetch(target).then(r => r.text()).then(t => res.send(t));
});

// JWT002 — jwt.verify without explicit algorithms list (alg confusion)
app.get('/me', (req, res) => {
  const payload = jwt.verify(req.headers.authorization, 'secret');
  res.json(payload);
});

// OAUTH001 — oauth callback without state verification
app.get('/oauth/callback', (req, res) => {
  const code = req.query.code;
  exchangeCodeForToken(code).then(token => res.json(token));
});

// FE007a — Object.assign prototype pollution
app.post('/user', (req, res) => {
  const user = Object.assign({}, req.body);
  saveUser(user);
  res.json(user);
});
