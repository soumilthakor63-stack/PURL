const express  = require('express');
const cors     = require('cors');
const https    = require('https');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => { res.setHeader('ngrok-skip-browser-warning', 'true'); next(); });
app.use(express.static(__dirname));

// ── MongoDB connection ─────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => console.error('❌  MongoDB error:', err.message));

// ── Schema ─────────────────────────────────────────────────────────────────
const scanSchema = new mongoose.Schema({
  user_id:    { type: String, required: true, index: true },
  url:        { type: String, required: true },
  domain:     { type: String },
  verdict:    { type: String },
  risk_level: { type: String },
  risk_score: { type: Number },
  stats: {
    harmless:   Number,
    malicious:  Number,
    suspicious: Number,
    undetected: Number
  },
  ai_analysis: { type: String },
  screenshot:  { type: String },
  scanned_by:  { type: String },
  timestamp:   { type: Date, default: Date.now }
});

const Scan = mongoose.model('Scan', scanSchema);

// ── Admin auth middleware ──────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Helper: extract domain ─────────────────────────────────────────────────
function extractDomain(url) {
  try {
    let u = url.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    return new URL(u).hostname.replace('www.', '');
  } catch { return url; }
}

// ── Helper: normalise URL for dupe check ──────────────────────────────────
function normaliseUrl(url) {
  return url.trim().toLowerCase().replace(/\/+$/, '').replace(/^https?:\/\//, '');
}

// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
//  SCAN — always fresh, upsert (1 record per URL per user)
// ══════════════════════════════════════════════════════════════════════════════
app.post('/webhook/url-check', async (req, res) => {
  const { url, user_id } = req.body;

  if (!url)     return res.status(400).json({ error: 'URL is required' });
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });

  const norm = normaliseUrl(url);
  const urlRegex = new RegExp('^' + norm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

  // Always forward to n8n — no caching, always fresh scan
  const payload = JSON.stringify({ url });
  const options = {
    hostname: 'purl-n8n.onrender.com',
    port: 443,
    path: '/webhook/url-check',
    method: 'POST',
    timeout: 120000,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'ngrok-skip-browser-warning': 'true'
    }
  };

  const proxyReq = https.request(options, (proxyRes) => {
    let body = '';
    proxyRes.on('data', chunk => body += chunk);
    proxyRes.on('end', async () => {
      try {
        const d      = JSON.parse(body);
        const result = Array.isArray(d) ? d[0] : d;

        const scanData = {
          user_id,
          url:         result.url || url,
          domain:      extractDomain(result.url || url),
          verdict:     result.verdict,
          risk_level:  result.risk_level,
          risk_score:  result.risk_level === 'LOW'    ? 15
                     : result.risk_level === 'MEDIUM' ? 55
                     : result.risk_level === 'HIGH'   ? 85 : 0,
          stats:       result.stats || {},
          ai_analysis: result.ai_analysis,
          screenshot:  result.screenshot,
          scanned_by:  result.scanned_by,
          timestamp:   new Date()
        };

        // Upsert — update existing record if same URL, insert if new
        // This keeps exactly 1 record per URL per user, no duplicates ever
        await Scan.findOneAndUpdate(
          { user_id, url: { $regex: urlRegex } },
          { $set: scanData },
          { upsert: true, new: true }
        );
      } catch (_) { /* save fail — still return result to user */ }

      res.setHeader('Content-Type', 'application/json');
      res.send(body);
    });
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    res.status(504).json({
      url, verdict: 'ERROR', risk_level: 'UNKNOWN',
      stats: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 },
      scanned_by: 'VirusTotal + Google Safe Browsing + URLScan.io',
      ai_analysis: 'Scan timed out. Please try again.', screenshot: null
    });
  });

  proxyReq.on('error', err => res.status(500).json({ error: err.message }));
  proxyReq.write(payload);
  proxyReq.end();
});


//  USER HISTORY   GET /history?user_id=xxx
// ══════════════════════════════════════════════════════════════════════════════
app.get('/history', async (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  try {
    const scans = await Scan.find({ user_id })
      .sort({ timestamp: -1 })
      .limit(50)
      .select('url domain verdict risk_level timestamp stats');
    res.json(scans);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES  (all protected by x-admin-token header)
// ══════════════════════════════════════════════════════════════════════════════

// Verify password
app.post('/admin/verify', (req, res) => {
  const { token } = req.body;
  res.json({ ok: token === process.env.ADMIN_TOKEN });
});

// Stats dashboard
app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const [total, malicious, safe, cached, users] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ verdict: 'MALICIOUS' }),
      Scan.countDocuments({ verdict: 'SAFE' }),
      Promise.resolve(0),
      Scan.distinct('user_id')
    ]);
    const recent = await Scan.find().sort({ timestamp: -1 }).limit(5)
      .select('url verdict risk_level timestamp user_id');
    res.json({ total, malicious, safe, cached, unique_users: users.length, recent });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// READ all scans (search + filter + paginate)
app.get('/admin/scans', adminAuth, async (req, res) => {
  try {
    const { search, risk_level, verdict, user_id, page = 1, limit = 20 } = req.query;
    const query = {};
    if (search)     query.url        = { $regex: search, $options: 'i' };
    if (risk_level) query.risk_level = risk_level.toUpperCase();
    if (verdict)    query.verdict    = verdict.toUpperCase();
    if (user_id)    query.user_id    = user_id;

    const total = await Scan.countDocuments(query);
    const scans = await Scan.find(query)
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    res.json({ total, page: parseInt(page), pages: Math.ceil(total / limit), scans });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// READ single
app.get('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json(scan);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CREATE manually
app.post('/admin/scans', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.create(req.body);
    res.status(201).json(scan);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// UPDATE
app.put('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json(scan);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// DELETE single
app.delete('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findByIdAndDelete(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE all scans for a user
app.delete('/admin/users/:uid/scans', adminAuth, async (req, res) => {
  try {
    const r = await Scan.deleteMany({ user_id: req.params.uid });
    res.json({ message: `Deleted ${r.deletedCount} scans` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(3000, () => console.log('🚀  PURL running at http://localhost:3000'));
