const express  = require('express');
const cors     = require('cors');
const https    = require('https');
const http     = require('http');
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
  user_id:         { type: String, required: true, index: true },
  url:             { type: String, required: true },
  domain:          { type: String },
  verdict:         { type: String },
  risk_level:      { type: String },
  risk_score:      { type: Number },
  stats: {
    harmless:   Number,
    malicious:  Number,
    suspicious: Number,
    undetected: Number
  },
  ai_analysis:       { type: String },
  gemini_verdict:    { type: String },   // NEW: SAFE | SUSPICIOUS | MALICIOUS
  gemini_analysis:   { type: String },   // NEW: Gemini's visual analysis text
  gemini_indicators: { type: [String] }, // NEW: list of red flags found
  screenshot:        { type: String },
  scanned_by:        { type: String },
  timestamp:         { type: Date, default: Date.now }
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

// ── Helper: fetch screenshot as base64 ────────────────────────────────────
// URLScan.io returns a screenshot URL. We download the image and convert to base64
// so Gemini Vision can analyze it directly.
function fetchImageAsBase64(imageUrl) {
  return new Promise((resolve) => {
    // Determine http vs https
    const lib = imageUrl.startsWith('https') ? https : http;
    lib.get(imageUrl, (res) => {
      // Handle redirects
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchImageAsBase64(res.headers.location).then(resolve);
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        resolve(buffer.toString('base64'));
      });
    }).on('error', () => resolve(null)); // if image fetch fails, return null
  });
}

// ── Known Official Brands Database ───────────────────────────────────────
// brand keyword → { official domain, login page, display name }
// If a URL contains a brand keyword but domain is NOT official → MALICIOUS
const KNOWN_BRANDS = {
  instagram:  { domain: 'instagram.com',      login: 'instagram.com/accounts/login',    name: 'Instagram' },
  insta:      { domain: 'instagram.com',      login: 'instagram.com/accounts/login',    name: 'Instagram' },
  facebook:   { domain: 'facebook.com',       login: 'facebook.com/login',              name: 'Facebook' },
  google:     { domain: 'google.com',         login: 'accounts.google.com',             name: 'Google' },
  gmail:      { domain: 'google.com',         login: 'accounts.google.com',             name: 'Gmail/Google' },
  youtube:    { domain: 'youtube.com',        login: 'accounts.google.com',             name: 'YouTube' },
  paypal:     { domain: 'paypal.com',         login: 'paypal.com/signin',               name: 'PayPal' },
  amazon:     { domain: 'amazon.com',         login: 'amazon.com/ap/signin',            name: 'Amazon' },
  microsoft:  { domain: 'microsoft.com',      login: 'login.microsoftonline.com',       name: 'Microsoft' },
  outlook:    { domain: 'microsoft.com',      login: 'login.microsoftonline.com',       name: 'Outlook/Microsoft' },
  apple:      { domain: 'apple.com',          login: 'appleid.apple.com',               name: 'Apple' },
  icloud:     { domain: 'apple.com',          login: 'appleid.apple.com',               name: 'iCloud/Apple' },
  netflix:    { domain: 'netflix.com',        login: 'netflix.com/login',               name: 'Netflix' },
  whatsapp:   { domain: 'whatsapp.com',       login: 'web.whatsapp.com',                name: 'WhatsApp' },
  linkedin:   { domain: 'linkedin.com',       login: 'linkedin.com/login',              name: 'LinkedIn' },
  snapchat:   { domain: 'snapchat.com',       login: 'accounts.snapchat.com',           name: 'Snapchat' },
  tiktok:     { domain: 'tiktok.com',         login: 'tiktok.com/login',                name: 'TikTok' },
  telegram:   { domain: 'telegram.org',       login: 'web.telegram.org',                name: 'Telegram' },
  yahoo:      { domain: 'yahoo.com',          login: 'login.yahoo.com',                 name: 'Yahoo' },
  twitter:    { domain: 'x.com',             login: 'x.com/i/flow/login',              name: 'X (Twitter)' },
  hdfc:       { domain: 'hdfcbank.com',       login: 'netbanking.hdfcbank.com',         name: 'HDFC Bank' },
  sbi:        { domain: 'onlinesbi.com',      login: 'onlinesbi.com',                   name: 'SBI' },
  icici:      { domain: 'icicibank.com',      login: 'icicibank.com',                   name: 'ICICI Bank' },
  axis:       { domain: 'axisbank.com',       login: 'axisbank.com',                    name: 'Axis Bank' },
  paytm:      { domain: 'paytm.com',          login: 'paytm.com',                       name: 'Paytm' },
  phonepe:    { domain: 'phonepe.com',        login: 'phonepe.com',                     name: 'PhonePe' },
  dropbox:    { domain: 'dropbox.com',        login: 'dropbox.com/login',               name: 'Dropbox' },
  github:     { domain: 'github.com',         login: 'github.com/login',               name: 'GitHub' },
  spotify:    { domain: 'spotify.com',        login: 'accounts.spotify.com',            name: 'Spotify' },
  binance:    { domain: 'binance.com',        login: 'binance.com/login',               name: 'Binance' },
  coinbase:   { domain: 'coinbase.com',       login: 'coinbase.com/signin',             name: 'Coinbase' },
};

// Free hosting — always suspicious when used with brand names
const FREE_HOSTING = [
  'netlify.app','github.io','vercel.app','web.app','firebaseapp.com',
  'glitch.me','repl.co','surge.sh','000webhostapp.com','weebly.com',
  'wixsite.com','blogspot.com','sites.google.com','azurewebsites.net',
  'herokuapp.com','pages.dev','ondigitalocean.app','fly.dev','railway.app'
];

// Shortened URLs
const SHORTENERS = [
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','rb.gy',
  'short.io','is.gd','buff.ly','tiny.cc','cutt.ly','shorturl.at'
];

// Leet speak decoder
function decodeLeet(str) {
  return str
    .replace(/0/g,'o').replace(/1/g,'i').replace(/3/g,'e')
    .replace(/4/g,'a').replace(/5/g,'s').replace(/6/g,'g')
    .replace(/7/g,'t').replace(/8/g,'b').replace(/9/g,'g')
    .replace(/@/g,'a').replace(/\$/g,'s');
}

// ── Main URL Analysis function ─────────────────────────────────────────────
function analyzeURL(rawUrl) {
  const flags      = [];
  let   urlVerdict = 'SAFE';
  let   detectedBrand = null;
  let   isFreeHost    = false;

  try {
    let u = rawUrl.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    const parsed   = new URL(u);
    const hostname = parsed.hostname.toLowerCase();
    const path     = parsed.pathname.toLowerCase();
    const parts    = hostname.split('.');
    const tld      = parts.slice(-2).join('.');

    // ── CHECK 1: Free hosting service ────────────────────────────
    const freeHostMatch = FREE_HOSTING.find(h => hostname.endsWith(h));
    if (freeHostMatch) {
      isFreeHost = true;
      flags.push('Hosted on free service "' + freeHostMatch + '" — official brands never host login pages here');
      urlVerdict = 'SUSPICIOUS';
    }

    // ── CHECK 2: Shortened URL ────────────────────────────────────
    if (SHORTENERS.some(s => hostname === s)) {
      flags.push('Shortened URL — real destination is hidden, cannot verify safety');
      urlVerdict = 'SUSPICIOUS';
    }

    // ── CHECK 3: Decode leet speak in domain ─────────────────────
    const freeHostParts = freeHostMatch ? freeHostMatch.split('.').length : 0;
    const subdomainPart = isFreeHost
      ? parts.slice(0, parts.length - freeHostParts).join('.')
      : hostname;
    const decoded = decodeLeet(subdomainPart);

    // ── CHECK 4: Brand name comparison ───────────────────────────
    const toCheck = [hostname, decoded, subdomainPart];

    Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
      const isInUrl = toCheck.some(s => s.includes(keyword));
      const isOfficial = hostname === info.domain
        || hostname.endsWith('.' + info.domain);

      if (isInUrl && !isOfficial) {
        detectedBrand = info.name;
        flags.push('FAKE ' + info.name.toUpperCase() + ' PAGE — domain "' + hostname + '" is NOT the real ' + info.name + ' site');
        flags.push('Real ' + info.name + ' login is: ' + info.login + ' — this is a phishing clone');

        if (decoded !== subdomainPart) {
          flags.push('Leet speak trick: "' + subdomainPart + '" decodes to "' + decoded + '" to impersonate ' + info.name);
        }
        if (isFreeHost) {
          flags.push(info.name + ' NEVER uses "' + tld + '" — this page is designed to steal credentials');
        }
        urlVerdict = 'MALICIOUS';
      }
    });

    // ── CHECK 5: Subdomain trick ──────────────────────────────────
    // e.g. instagram.com.evil.net — real domain is evil.net
    if (parts.length > 2) {
      Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
        const subParts = parts.slice(0, -2);
        if (subParts.some(p => p.includes(keyword)) && !hostname.endsWith(info.domain)) {
          detectedBrand = detectedBrand || info.name;
          flags.push('Subdomain trick: "' + keyword + '" appears as subdomain but real domain is "' + tld + '"');
          urlVerdict = 'MALICIOUS';
        }
      });
    }

    // ── CHECK 6: Free hosting + suspicious path (no brand found) ─
    if (isFreeHost && !detectedBrand) {
      const suspWords = ['login','signin','verify','account','password','secure','banking','confirm','auth'];
      const foundWord = suspWords.find(w => path.includes(w));
      if (foundWord) {
        flags.push('Free hosting + suspicious path keyword "' + foundWord + '" — likely a phishing page');
        urlVerdict = 'SUSPICIOUS';
      }
    }

    // ── CHECK 7: Hyphen brand trick ───────────────────────────────
    if (hostname.includes('-')) {
      Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
        if (hostname.includes(keyword) && !hostname.endsWith(info.domain)) {
          flags.push('Hyphen trick: "' + hostname + '" mimics ' + info.name + ' using hyphens');
          urlVerdict = urlVerdict === 'SAFE' ? 'SUSPICIOUS' : urlVerdict;
        }
      });
    }

  } catch (_) {}

  console.log('URL verdict:', urlVerdict, '| brand:', detectedBrand || 'none', '| flags:', flags.length);
  return { urlFlags: flags, urlVerdict, detectedBrand };
}

// ── Gemini Vision Analysis ─────────────────────────────────────────────────
// Sends screenshot + URL + pre-analysis flags to Gemini 2.0 Flash.
// Gemini does VISUAL comparison against the real latest version of the page.
async function analyzeWithGemini(screenshotBase64, url, domain, urlFlags) {
  return new Promise((resolve) => {

    // Build pre-analysis context to give Gemini a head start
    const preAnalysisContext = urlFlags && urlFlags.length > 0
      ? `\nURL pre-analysis already found these red flags:\n${urlFlags.map((f,i) => `${i+1}. ${f}`).join('\n')}\n`
      : '\nURL pre-analysis found no obvious domain tricks.\n';

    if (!screenshotBase64) {
      // No screenshot — still run URL-only analysis via Gemini text mode
      console.log('⚠️  No screenshot — running URL-only Gemini analysis');
    }

    const prompt = `You are an expert cybersecurity analyst specializing in phishing detection, visual brand impersonation, and URL forensics.

TARGET URL: "${url}"
DOMAIN: "${domain}"
${preAnalysisContext}

${screenshotBase64 ? 'I am providing you a LIVE SCREENSHOT of this webpage captured right now by URLScan.io.' : 'No screenshot is available. Analyze based on URL and domain only.'}

YOUR TASK — perform ALL of the following checks:

━━━ PART 1: URL & DOMAIN ANALYSIS ━━━
1. LEET SPEAK: Does the domain replace letters with numbers? (l0gin = login, 1nstagram = instagram, paypa1 = paypal, instaqram = instagram)
2. BRAND IN WRONG DOMAIN: Does the URL contain a brand name (Instagram, Google, PayPal, Facebook, Apple, Microsoft, Amazon, Netflix, WhatsApp, any Indian bank like HDFC/SBI/ICICI) but the actual domain is NOT the official one?
3. SUBDOMAIN TRICK: Is a real brand used as a subdomain to fake legitimacy? Example: instagram.com.evil.net — the real domain is evil.net, not instagram.com
4. FREE HOSTING: Is a free hosting service (netlify.app, github.io, vercel.app, web.app, firebase, glitch.me) being used to host what looks like an official brand page?
5. SUSPICIOUS PATH WORDS: Does the URL path contain words like login, verify, secure, update, banking, confirm, password, account, suspended, locked?
6. HYPHEN TRICK: Does the domain use hyphens with brand names? (secure-instagram.com, paypal-verify.com)

━━━ PART 2: VISUAL SCREENSHOT ANALYSIS ━━━
${screenshotBase64 ? `
Compare what you see in the screenshot against what the REAL CURRENT official page of that brand looks like TODAY (use your most up-to-date knowledge of how these sites currently look — not old versions).

7. BRAND IMPERSONATION: Does this page visually copy a well-known brand? Check logo, colors, layout, fonts, button styles.
8. OUTDATED CLONE: Does the page look like an OLD version of a brand's login page that has since been redesigned? (e.g. old Instagram login vs current Instagram login) — this is a strong phishing indicator because attackers copy old templates.
9. LOGIN FORM ON WRONG DOMAIN: Is there a username/password/email input form on a page that is NOT hosted on the brand's official domain?
10. QUALITY INDICATORS: Are there pixelated logos, broken images, mismatched fonts, strange spacing, or copy-paste artifacts?
11. URGENCY LANGUAGE: Are there phrases like "Your account will be suspended", "Verify now", "Act immediately", "Unusual activity detected"?
12. MISMATCH: Does the page CLAIM to be one brand but the URL clearly belongs to a different/unknown domain?
` : '7-12. No screenshot available for visual analysis.'}

━━━ CRITICAL RULE ━━━
Even if VirusTotal or Google Safe Browsing said this URL is SAFE, YOU must make your OWN independent judgment based on the URL structure and visual evidence. New phishing sites are not yet in threat databases. If the URL has brand tricks AND the page visually impersonates a brand — it IS malicious regardless of what other tools say.

━━━ OUTPUT FORMAT ━━━
Respond ONLY with this exact JSON. No markdown. No extra text before or after:
{
  "verdict": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "summary": "One clear sentence describing exactly what this page is and why it is safe/suspicious/malicious",
  "indicators": ["specific red flag 1", "specific red flag 2", "...list every red flag found"],
  "brand_impersonated": "exact brand name if impersonating one, otherwise null"
}`;

    const requestBody = JSON.stringify({
      contents: [{
        parts: [
          // Screenshot first if available
          ...(screenshotBase64 ? [{
            inline_data: {
              mime_type: 'image/png',
              data: screenshotBase64
            }
          }] : []),
          { text: prompt }
        ]
      }],
      // Enable Google Search grounding — Gemini checks LATEST real pages live
      tools: [{
        google_search: {}
      }],
      generationConfig: {
        temperature: 0.05,
        maxOutputTokens: 1024
      }
    });

    const apiKey = process.env.GEMINI_API_KEY;
    const options = {
      hostname: 'generativelanguage.googleapis.com',
      port: 443,
      path: `/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestBody)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      console.log('📡 Gemini HTTP status:', res.statusCode);
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log('📦 Gemini raw data (first 200 chars):', data.substring(0, 200));
        try {
          const parsed = JSON.parse(data);

          // Log full raw response for debugging
          const text = parsed.candidates?.[0]?.content?.parts?.[0]?.text || '';
          console.log('🔍 Gemini raw response:', text.substring(0, 300));

          // ── Robust JSON extraction ─────────────────────────────
          // Gemini sometimes wraps JSON in markdown, adds extra text,
          // or puts explanation before/after the JSON block.
          // Try multiple extraction strategies:

          let result = null;

          // Strategy 1: direct parse (cleanest case)
          try {
            const clean = text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
            result = JSON.parse(clean);
          } catch (_) {}

          // Strategy 2: extract first {...} block from the text
          if (!result) {
            try {
              const match = text.match(/\{[\s\S]*\}/);
              if (match) result = JSON.parse(match[0]);
            } catch (_) {}
          }

          // Strategy 3: Gemini returned plain text — parse key phrases manually
          if (!result) {
            console.log('⚠️  JSON parse failed — doing keyword extraction from text');
            const upper = text.toUpperCase();
            const isMalicious  = upper.includes('MALICIOUS') || upper.includes('PHISHING') || upper.includes('FAKE') || upper.includes('IMPERSONAT');
            const isSuspicious = upper.includes('SUSPICIOUS') || upper.includes('SUSPICIOUS') || upper.includes('POTENTIALLY');
            result = {
              verdict:             isMalicious ? 'MALICIOUS' : isSuspicious ? 'SUSPICIOUS' : 'SAFE',
              confidence:          'MEDIUM',
              summary:             text.substring(0, 300).trim() || 'Visual analysis complete.',
              indicators:          [],
              brand_impersonated:  null
            };
            // Try to extract brand name
            const brandMatch = text.match(/impersonat(?:es?|ing)\s+([A-Z][a-zA-Z]+)/i);
            if (brandMatch) result.brand_impersonated = brandMatch[1];
          }

          console.log('✅ Gemini parsed verdict:', result.verdict);
          resolve({
            gemini_verdict:    (result.verdict             || 'UNKNOWN').toUpperCase(),
            gemini_analysis:   result.summary              || result.description || text.substring(0, 200) || 'Analysis complete.',
            gemini_confidence: (result.confidence          || 'MEDIUM').toUpperCase(),
            gemini_indicators: Array.isArray(result.indicators) ? result.indicators : [],
            gemini_brand:      result.brand_impersonated   || null
          });

        } catch (e) {
          // Last resort — log what we got and return UNKNOWN
          console.log('❌ Gemini total parse failure. Raw data:', data.substring(0, 400));
          resolve({
            gemini_verdict:    'UNKNOWN',
            gemini_analysis:   'Gemini response could not be read. Raw: ' + data.substring(0, 100),
            gemini_confidence: 'LOW',
            gemini_indicators: []
          });
        }
      });
    });

    req.on('error', () => resolve({
      gemini_verdict:    'UNKNOWN',
      gemini_analysis:   'Gemini API call failed.',
      gemini_indicators: []
    }));

    req.setTimeout(30000, () => {
      req.destroy();
      resolve({
        gemini_verdict:    'UNKNOWN',
        gemini_analysis:   'Gemini analysis timed out.',
        gemini_indicators: []
      });
    });

    req.write(requestBody);
    req.end();
  });
}

// ── Helper: merge verdicts ─────────────────────────────────────────────────
// If Gemini says MALICIOUS but APIs say SAFE, we trust Gemini for new sites.
// Final verdict = the more severe of the two.
function mergeVerdicts(apiVerdict, geminiVerdict) {
  const severity = { 'SAFE': 0, 'LOW': 1, 'MEDIUM': 2, 'SUSPICIOUS': 2, 'HIGH': 3, 'MALICIOUS': 4, 'CRITICAL': 5, 'UNKNOWN': 0 };
  const api = (apiVerdict || 'UNKNOWN').toUpperCase();
  const gem = (geminiVerdict || 'UNKNOWN').toUpperCase();
  return severity[gem] > severity[api] ? gem : api;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SCAN — always fresh, upsert (1 record per URL per user)
// ══════════════════════════════════════════════════════════════════════════════
app.post('/webhook/url-check', async (req, res) => {
  const { url, user_id } = req.body;

  if (!url)     return res.status(400).json({ error: 'URL is required' });
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });

  const norm = normaliseUrl(url);
  const urlRegex = new RegExp('^' + norm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

  // ── Step 0: URL pre-analysis (instant, no API needed) ────────────
  const { urlFlags, urlVerdict, detectedBrand: urlBrand } = analyzeURL(url);
  if (urlFlags.length > 0) console.log('URL flags found:', urlFlags.length, '| verdict:', urlVerdict);

  // Always forward to n8n — always fresh scan
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

        // ── Step 1: Get screenshot from result ────────────────────
        const screenshotUrl = result.screenshot || null;
        const domain        = extractDomain(result.url || url);

        // ── Step 2: Download screenshot as base64 ─────────────────
        let screenshotBase64 = null;
        if (screenshotUrl) {
          console.log('📸 Fetching screenshot for Gemini analysis...');
          screenshotBase64 = await fetchImageAsBase64(screenshotUrl);
        }

        // ── Step 3: Run Gemini Vision analysis ────────────────────
        console.log('🤖 Running Gemini Vision analysis...');
        const geminiResult = await analyzeWithGemini(screenshotBase64, result.url || url, domain, urlFlags);
        console.log('✅ Gemini verdict:', geminiResult.gemini_verdict);

        // ── Step 4: Merge all verdicts ────────────────────────────
        // Final = most severe of: API verdict + URL pre-analysis + Gemini visual
        const finalVerdict = mergeVerdicts(
          mergeVerdicts(result.verdict, urlVerdict),
          geminiResult.gemini_verdict
        );

        // Add URL flags into Gemini indicators so they all show on UI
        const allIndicators = [
          ...urlFlags,
          ...(geminiResult.gemini_indicators || [])
        ];

        // ── Step 5: Build full response ───────────────────────────
        const enrichedResult = {
          ...result,
          verdict:           finalVerdict,
          gemini_verdict:    geminiResult.gemini_verdict,
          gemini_analysis:   geminiResult.gemini_analysis,
          gemini_confidence: geminiResult.gemini_confidence,
          gemini_indicators: allIndicators,
          gemini_brand:      geminiResult.gemini_brand,
          url_verdict:       urlVerdict
        };

        // ── Step 6: Upsert into MongoDB ───────────────────────────
        const scanData = {
          user_id,
          url:               enrichedResult.url || url,
          domain,
          verdict:           enrichedResult.verdict,
          risk_level:        enrichedResult.risk_level,
          risk_score:        enrichedResult.risk_level === 'LOW'    ? 15
                           : enrichedResult.risk_level === 'MEDIUM' ? 55
                           : enrichedResult.risk_level === 'HIGH'   ? 85 : 0,
          stats:             enrichedResult.stats || {},
          ai_analysis:       enrichedResult.ai_analysis,
          gemini_verdict:    geminiResult.gemini_verdict,
          gemini_analysis:   geminiResult.gemini_analysis,
          gemini_indicators: allIndicators,
          screenshot:        enrichedResult.screenshot,
          scanned_by:        enrichedResult.scanned_by,
          timestamp:         new Date()
        };

        await Scan.findOneAndUpdate(
          { user_id, url: { $regex: urlRegex } },
          { $set: scanData },
          { upsert: true, new: true }
        );

        // ── Step 7: Send enriched result to frontend ──────────────
        res.setHeader('Content-Type', 'application/json');
        res.json(enrichedResult);

      } catch (err) {
        console.error('Scan processing error:', err.message);
        res.setHeader('Content-Type', 'application/json');
        res.send(body); // fallback: send original n8n result
      }
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
app.get('/history', async (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  try {
    const scans = await Scan.find({ user_id })
      .sort({ timestamp: -1 })
      .limit(50)
      .select('url domain verdict risk_level timestamp stats gemini_verdict');
    res.json(scans);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── ADMIN ROUTES (all protected) ──────────────────────────────────────────
app.post('/admin/verify', (req, res) => {
  const { token } = req.body;
  res.json({ ok: token === process.env.ADMIN_TOKEN });
});

app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const [total, malicious, safe, users] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ verdict: 'MALICIOUS' }),
      Scan.countDocuments({ verdict: 'SAFE' }),
      Scan.distinct('user_id')
    ]);
    const recent = await Scan.find().sort({ timestamp: -1 }).limit(5)
      .select('url verdict risk_level timestamp user_id gemini_verdict');
    res.json({ total, malicious, safe, unique_users: users.length, recent });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/scans', adminAuth, async (req, res) => {
  try {
    const { search, risk_level, verdict, user_id, page = 1, limit = 20 } = req.query;
    const query = {};
    if (search)     query.url        = { $regex: search, $options: 'i' };
    if (risk_level) query.risk_level = risk_level.toUpperCase();
    if (verdict)    query.verdict    = verdict.toUpperCase();
    if (user_id)    query.user_id    = user_id;
    const total = await Scan.countDocuments(query);
    const scans = await Scan.find(query).sort({ timestamp: -1 }).skip((page-1)*limit).limit(parseInt(limit));
    res.json({ total, page: parseInt(page), pages: Math.ceil(total/limit), scans });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json(scan);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/scans', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.create(req.body);
    res.status(201).json(scan);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json(scan);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/admin/scans/:id', adminAuth, async (req, res) => {
  try {
    const scan = await Scan.findByIdAndDelete(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Deleted', id: req.params.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/admin/users/:uid/scans', adminAuth, async (req, res) => {
  try {
    const r = await Scan.deleteMany({ user_id: req.params.uid });
    res.json({ message: `Deleted ${r.deletedCount} scans` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(3000, () => console.log('🚀  PURL running at http://localhost:3000'));
