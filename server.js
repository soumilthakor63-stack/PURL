const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

// Skip ngrok warning page
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  next();
});

app.use(express.static(__dirname));

app.post('/webhook/url-check', (req, res) => {
  const data = JSON.stringify(req.body);

  const options = {
    hostname: 'purl-n8n.onrender.com',
    port: 443,
    path: '/webhook/url-check',
    method: 'POST',
    timeout: 120000,
    protocol: 'https:',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'ngrok-skip-browser-warning': 'true'
    }
  };

  const proxyReq = https.request(options, (proxyRes) => {
    let body = '';
    proxyRes.on('data', chunk => body += chunk);
    proxyRes.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      res.send(body);
    });
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    res.status(504).json({
      url: req.body.url,
      verdict: 'ERROR',
      risk_level: 'UNKNOWN',
      stats: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 },
      scanned_by: 'VirusTotal + Google Safe Browsing + URLScan.io',
      ai_analysis: 'Scan timed out. Please try again.',
      screenshot: null
    });
  });

  proxyReq.on('error', (err) => {
    res.status(500).json({ error: err.message });
  });

  proxyReq.write(data);
  proxyReq.end();
});

app.listen(3000, () => {
  console.log('PURL running at http://localhost:3000');
});