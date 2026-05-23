require('dotenv').config();
const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const mongoose = require('mongoose');


const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => { res.setHeader('ngrok-skip-browser-warning', 'true'); next(); });
app.use(express.static(__dirname));

// ── MongoDB ────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => console.error('❌  MongoDB error:', err.message));

// ── Schema ─────────────────────────────────────────────────────────────────
const scanSchema = new mongoose.Schema({
  user_id: { type: String, required: true, index: true },
  url: { type: String, required: true },
  domain: { type: String },
  verdict: { type: String },
  risk_level: { type: String },
  risk_score: { type: Number },
  stats: {
    harmless: Number,
    malicious: Number,
    suspicious: Number,
    undetected: Number
  },
  ai_analysis: { type: String },
  gemini_verdict: { type: String },
  gemini_analysis: { type: String },
  gemini_indicators: { type: [String] },
  gemini_brand: { type: String },
  groq_verdict: { type: String },
  groq_analysis: { type: String },
  ai_conflict: { type: Boolean },
  screenshot: { type: String },
  scanned_by: { type: String },
  timestamp: { type: Date, default: Date.now }
});
const Scan = mongoose.model('Scan', scanSchema);

// ── Admin auth ─────────────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== process.env.ADMIN_TOKEN)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── Helpers ────────────────────────────────────────────────────────────────
function extractDomain(url) {
  try {
    let u = url.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    return new URL(u).hostname.replace('www.', '');
  } catch { return url; }
}

function normaliseUrl(url) {
  return url.trim().toLowerCase().replace(/\/+$/, '').replace(/^https?:\/\//, '');
}

function fetchImageAsBase64(imageUrl) {
  return new Promise((resolve) => {
    const lib = imageUrl.startsWith('https') ? https : http;
    lib.get(imageUrl, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchImageAsBase64(res.headers.location).then(resolve);
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('base64')));
    }).on('error', () => resolve(null));
  });
}

// ── Google Search — find official URL for brand ───────────────────────────
// Searches Google for "site:brand official" to find the real domain
// Then compares with submitted URL to detect fakes
async function searchOfficialUrl(url, domain) {
  return new Promise((resolve) => {
    const apiKey = process.env.GOOGLE_SEARCH_API_KEY;
    const cx = process.env.GOOGLE_SEARCH_CX;

    // Extract brand-like name from domain
    // e.g. littlecaesurs.com → "littlecaesurs"
    // e.g. instaqram-l0g1n.netlify.app → "instaqram"
    const domainBase = domain.split('.')[0]
      .replace(/-/g, ' ')
      .replace(/l0g1n|login|verify|secure|update/g, '')
      .trim();

    if (!apiKey || !cx || !domainBase || domainBase.length < 4) {
      return resolve({ officialDomain: null, isFake: false, searchVerdict: null });
    }

    const query = encodeURIComponent('"' + domainBase + '" official website');
    const searchUrl = '/customsearch/v1?key=' + apiKey + '&cx=' + cx + '&q=' + query + '&num=3';

    const opts = {
      hostname: 'www.googleapis.com',
      port: 443,
      path: searchUrl,
      method: 'GET'
    };

    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const items = parsed.items || [];
          if (items.length === 0) return resolve({ officialDomain: null, isFake: false, searchVerdict: null });

          // Get domains from top results
          const topDomains = items.slice(0, 3).map(item => {
            try { return new URL(item.link).hostname.replace('www.', ''); }
            catch (_) { return ''; }
          }).filter(Boolean);

          console.log('🔍 Google search for "' + domainBase + '" → top domains:', topDomains);

          // Check if submitted domain matches any top result
          const isOfficial = topDomains.some(d => domain === d || domain.endsWith('.' + d));

          if (!isOfficial && topDomains.length > 0) {
            // Submitted domain is NOT in top Google results for this brand name
            // This is a strong signal it's fake
            const realDomain = topDomains[0];
            console.log('⚠️ Domain mismatch — submitted:', domain, '| Google says real site is:', realDomain);
            return resolve({
              officialDomain: realDomain,
              isFake: true,
              searchVerdict: 'SUSPICIOUS',
              searchFlag: 'Google Search shows the real "' + domainBase + '" website is "' + realDomain + '" — submitted URL "' + domain + '" does not match'
            });
          }

          resolve({ officialDomain: topDomains[0] || null, isFake: false, searchVerdict: null });
        } catch (_) {
          resolve({ officialDomain: null, isFake: false, searchVerdict: null });
        }
      });
    });

    req.on('error', () => resolve({ officialDomain: null, isFake: false, searchVerdict: null }));
    req.setTimeout(8000, () => { req.destroy(); resolve({ officialDomain: null, isFake: false, searchVerdict: null }); });
    req.end();
  });
}

// ── Known Brands ───────────────────────────────────────────────────────────
const KNOWN_BRANDS = {
  instagram: { domain: 'instagram.com', login: 'instagram.com/accounts/login', name: 'Instagram' },
  insta: { domain: 'instagram.com', login: 'instagram.com/accounts/login', name: 'Instagram' },
  facebook: { domain: 'facebook.com', login: 'facebook.com/login', name: 'Facebook' },
  google: { domain: 'google.com', login: 'accounts.google.com', name: 'Google' },
  gmail: { domain: 'google.com', login: 'accounts.google.com', name: 'Gmail/Google' },
  youtube: { domain: 'youtube.com', login: 'accounts.google.com', name: 'YouTube' },
  paypal: { domain: 'paypal.com', login: 'paypal.com/signin', name: 'PayPal' },
  amazon: { domain: 'amazon.com', login: 'amazon.com/ap/signin', name: 'Amazon' },
  microsoft: { domain: 'microsoft.com', login: 'login.microsoftonline.com', name: 'Microsoft' },
  outlook: { domain: 'microsoft.com', login: 'login.microsoftonline.com', name: 'Outlook/Microsoft' },
  apple: { domain: 'apple.com', login: 'appleid.apple.com', name: 'Apple' },
  icloud: { domain: 'apple.com', login: 'appleid.apple.com', name: 'iCloud/Apple' },
  netflix: { domain: 'netflix.com', login: 'netflix.com/login', name: 'Netflix' },
  whatsapp: { domain: 'whatsapp.com', login: 'web.whatsapp.com', name: 'WhatsApp' },
  linkedin: { domain: 'linkedin.com', login: 'linkedin.com/login', name: 'LinkedIn' },
  snapchat: { domain: 'snapchat.com', login: 'accounts.snapchat.com', name: 'Snapchat' },
  tiktok: { domain: 'tiktok.com', login: 'tiktok.com/login', name: 'TikTok' },
  telegram: { domain: 'telegram.org', login: 'web.telegram.org', name: 'Telegram' },
  yahoo: { domain: 'yahoo.com', login: 'login.yahoo.com', name: 'Yahoo' },
  twitter: { domain: 'x.com', login: 'x.com/i/flow/login', name: 'X (Twitter)' },
  hdfc: { domain: 'hdfcbank.com', login: 'netbanking.hdfcbank.com', name: 'HDFC Bank' },
  sbi: { domain: 'onlinesbi.com', login: 'onlinesbi.com', name: 'SBI' },
  icici: { domain: 'icicibank.com', login: 'icicibank.com', name: 'ICICI Bank' },
  axis: { domain: 'axisbank.com', login: 'axisbank.com', name: 'Axis Bank' },
  paytm: { domain: 'paytm.com', login: 'paytm.com', name: 'Paytm' },
  phonepe: { domain: 'phonepe.com', login: 'phonepe.com', name: 'PhonePe' },
  dropbox: { domain: 'dropbox.com', login: 'dropbox.com/login', name: 'Dropbox' },
  github: { domain: 'github.com', login: 'github.com/login', name: 'GitHub' },
  spotify: { domain: 'spotify.com', login: 'accounts.spotify.com', name: 'Spotify' },
  binance: { domain: 'binance.com', login: 'binance.com/login', name: 'Binance' },
  coinbase: { domain: 'coinbase.com', login: 'coinbase.com/signin', name: 'Coinbase' },
  // Skincare / Beauty
  rhodeskin: { domain: 'rhodeskin.com', login: 'rhodeskin.com', name: 'Rhode Skin' },
  // Food & Retail
  littlecaesars: { domain: 'littlecaesars.com', login: 'littlecaesars.com', name: 'Little Caesars' },
  mcdonalds: { domain: 'mcdonalds.com', login: 'mcdonalds.com', name: "McDonald's" },
  dominos: { domain: 'dominos.com', login: 'dominos.com', name: "Domino's" },
  starbucks: { domain: 'starbucks.com', login: 'starbucks.com', name: 'Starbucks' },
  walmart: { domain: 'walmart.com', login: 'walmart.com', name: 'Walmart' },
  flipkart: { domain: 'flipkart.com', login: 'flipkart.com', name: 'Flipkart' },
  myntra: { domain: 'myntra.com', login: 'myntra.com', name: 'Myntra' },
  swiggy: { domain: 'swiggy.com', login: 'swiggy.com', name: 'Swiggy' },
  zomato: { domain: 'zomato.com', login: 'zomato.com', name: 'Zomato' },
  // Crypto
  metamask: { domain: 'metamask.io', login: 'metamask.io', name: 'MetaMask' },
  opensea: { domain: 'opensea.io', login: 'opensea.io', name: 'OpenSea' },
  // Gaming
  steam: { domain: 'steampowered.com', login: 'store.steampowered.com', name: 'Steam' },
  epicgames: { domain: 'epicgames.com', login: 'epicgames.com', name: 'Epic Games' },
  roblox: { domain: 'roblox.com', login: 'roblox.com', name: 'Roblox' },
};

const FREE_HOSTING = [
  'netlify.app', 'github.io', 'vercel.app', 'web.app', 'firebaseapp.com',
  'glitch.me', 'repl.co', 'surge.sh', '000webhostapp.com', 'weebly.com',
  'wixsite.com', 'blogspot.com', 'sites.google.com', 'azurewebsites.net',
  'herokuapp.com', 'pages.dev', 'ondigitalocean.app', 'fly.dev', 'railway.app'
];

const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'rb.gy',
  'short.io', 'is.gd', 'buff.ly', 'tiny.cc', 'cutt.ly', 'shorturl.at'
];

function decodeLeet(str) {
  return str
    .replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/6/g, 'g')
    .replace(/7/g, 't').replace(/8/g, 'b').replace(/@/g, 'a');
}

// ── URL Analysis ───────────────────────────────────────────────────────────
function analyzeURL(rawUrl) {
  const flags = [];
  let urlVerdict = 'SAFE';
  let detectedBrand = null;
  let isFreeHost = false;

  try {
    let u = rawUrl.trim();
    if (!u.startsWith('http')) u = 'https://' + u;
    const parsed = new URL(u);
    const hostname = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    const parts = hostname.split('.');
    const tld = parts.slice(-2).join('.');

    const freeHostMatch = FREE_HOSTING.find(h => hostname.endsWith(h));
    if (freeHostMatch) {
      isFreeHost = true;
      flags.push('Hosted on free service "' + freeHostMatch + '" — official brands never host login pages here');
      urlVerdict = 'SUSPICIOUS';
    }

    if (SHORTENERS.some(s => hostname === s)) {
      flags.push('Shortened URL — real destination is hidden');
      urlVerdict = 'SUSPICIOUS';
    }

    const freeHostParts = freeHostMatch ? freeHostMatch.split('.').length : 0;
    const subdomainPart = isFreeHost
      ? parts.slice(0, parts.length - freeHostParts).join('.')
      : hostname;
    const decoded = decodeLeet(subdomainPart);
    const toCheck = [hostname, decoded, subdomainPart];

    Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
      const isInUrl = toCheck.some(s => s.includes(keyword));
      const isOfficial = hostname === info.domain || hostname.endsWith('.' + info.domain);
      if (isInUrl && !isOfficial) {
        detectedBrand = info.name;
        flags.push('FAKE ' + info.name.toUpperCase() + ' PAGE — "' + hostname + '" is NOT ' + info.domain);
        flags.push('Real ' + info.name + ' login: ' + info.login + ' — this is a phishing clone');
        if (decoded !== subdomainPart)
          flags.push('Leet speak trick: "' + subdomainPart + '" decodes to "' + decoded + '" to impersonate ' + info.name);
        if (isFreeHost)
          flags.push(info.name + ' NEVER uses "' + tld + '" — credential theft page');
        urlVerdict = 'MALICIOUS';
      }
    });

    if (parts.length > 2) {
      Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
        const subParts = parts.slice(0, -2);
        if (subParts.some(p => p.includes(keyword)) && !hostname.endsWith(info.domain)) {
          detectedBrand = detectedBrand || info.name;
          flags.push('Subdomain trick: "' + keyword + '" used as subdomain, real domain is "' + tld + '"');
          urlVerdict = 'MALICIOUS';
        }
      });
    }

    if (isFreeHost && !detectedBrand) {
      const suspWords = ['login', 'signin', 'verify', 'account', 'password', 'secure', 'banking', 'confirm', 'auth'];
      const found = suspWords.find(w => path.includes(w));
      if (found) {
        flags.push('Free hosting + suspicious path "' + found + '" — likely phishing page');
        urlVerdict = 'SUSPICIOUS';
      }
    }

    if (hostname.includes('-')) {
      Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
        if (hostname.includes(keyword) && !hostname.endsWith(info.domain)) {
          flags.push('Hyphen trick: "' + hostname + '" mimics ' + info.name);
          if (urlVerdict === 'SAFE') urlVerdict = 'SUSPICIOUS';
        }
      });
    }

    // CHECK: Typosquatting detection ────────────────────────────────
    // Checks if domain is a slight misspelling of a known brand domain
    // e.g. littlecaesurs.com vs littlecaesars.com
    const brandDomains = Object.values(KNOWN_BRANDS).map(b => b.domain);
    const cleanHostname = hostname.replace('www.', '');

    // Simple character substitution check
    for (const brandDomain of brandDomains) {
      if (cleanHostname === brandDomain) break; // exact match = legit
      const brandName = brandDomain.split('.')[0]; // e.g. "littlecaesars"
      const hostBase = cleanHostname.split('.')[0]; // e.g. "littlecaesurs"

      // Only check if lengths are similar (within 3 chars)
      if (Math.abs(brandName.length - hostBase.length) <= 3 && brandName.length > 5) {
        // Count character differences
        let diff = 0;
        const minLen = Math.min(brandName.length, hostBase.length);
        for (let ci = 0; ci < minLen; ci++) {
          if (brandName[ci] !== hostBase[ci]) diff++;
        }
        diff += Math.abs(brandName.length - hostBase.length);

        // 1-2 character difference = likely typosquat
        if (diff >= 1 && diff <= 2 && hostBase.length > 5) {
          const info = Object.values(KNOWN_BRANDS).find(b => b.domain === brandDomain);
          const brandDisplayName = info ? info.name : brandDomain;
          flags.push('Typosquatting detected: "' + cleanHostname + '" is a misspelling of "' + brandDomain + '" (' + brandDisplayName + ')');
          flags.push('This domain differs by only ' + diff + ' character(s) from the real ' + brandDisplayName + ' site — classic typosquat trick');
          detectedBrand = detectedBrand || brandDisplayName;
          if (urlVerdict === 'SAFE') urlVerdict = 'SUSPICIOUS';
          break;
        }
      }
    }

    // CHECK: Cybercrime path keywords — runs on ANY domain ──────────
    const cybercrimePaths = [
      'webshell', 'shellsell', 'shellmarket', 'exploitmarket',
      'malware', 'ransomware', 'botnet', 'stealer', 'keylogger',
      'phishkit', 'ddos', 'carding', 'cvvshop', 'fullz', 'dumpshop',
      'cracking', 'darkmarket', 'blackmarket', 'hackforum',
      'stealerlogs', 'infosteal', 'crypter', 'accountshop',
      'combolist', 'leaksite', 'ratshop', 'spyware'
    ];
    const fullPath = path.replace(/-/g, '').replace(/_/g, '');
    const foundCrime = cybercrimePaths.find(w => fullPath.includes(w));
    if (foundCrime) {
      flags.push('Cybercrime keyword "' + foundCrime + '" in URL path — this page likely sells or distributes illegal hacking tools or stolen data');
      flags.push('URL path matches known cybercrime marketplace pattern — do not visit');
      urlVerdict = 'MALICIOUS';
    }

    // CHECK: sell/market + hacking combo on non-mainstream domains ──
    const mainstream = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com',
      'microsoft.com', 'apple.com', 'github.com', 'twitter.com', 'x.com',
      'reddit.com', 'wikipedia.org', 'linkedin.com', 'instagram.com', 'netflix.com'];
    const isMainstream = mainstream.some(d => hostname.endsWith(d));
    if (!isMainstream) {
      const hasMarket = fullPath.includes('sell') || fullPath.includes('market') || fullPath.includes('shop');
      const hasHack = fullPath.includes('shell') || fullPath.includes('hack') ||
        fullPath.includes('exploit') || fullPath.includes('crack') ||
        fullPath.includes('leak') || fullPath.includes('dump') ||
        fullPath.includes('rat') || fullPath.includes('stealer');
      if (hasMarket && hasHack) {
        flags.push('Suspicious combination: marketplace/selling + hacking keywords in URL path — likely illegal cybercrime marketplace');
        urlVerdict = 'MALICIOUS';
      }
    }

    // CHECK: Rare or unusual TLDs ─────────────────────────────────────
    const rareTLDs = ['.mobile', '.xyz', '.top', '.click', '.link', '.online',
      '.site', '.website', '.tech', '.icu', '.gq', '.tk', '.ml', '.cf', '.ga',
      '.pw', '.cc', '.ws', '.biz', '.info'];
    const hasRareTLD = rareTLDs.some(t => hostname.endsWith(t));
    if (hasRareTLD && urlVerdict === 'SAFE') {
      flags.push('Unusual TLD ".' + tld.split('.').pop() + '" — rarely used by legitimate businesses, commonly used in phishing and scam sites');
      urlVerdict = 'SUSPICIOUS';
    }

  } catch (_) { }

  console.log('URL verdict:', urlVerdict, '| brand:', detectedBrand || 'none', '| flags:', flags.length);
  return { urlFlags: flags, urlVerdict, detectedBrand };
}

// ── Gemini Analysis — URL Grounding with retry ────────────────────────────
// Sends URL to Gemini like a chat: "is this safe to visit?"
// Uses Google Search grounding so Gemini can research the URL live
// Retries without grounding if first attempt is blocked
async function analyzeWithGemini(screenshotBase64, url, domain, urlFlags) {
  return new Promise((resolve) => {

    const flagContext = urlFlags && urlFlags.length > 0
      ? "\nOur scanner already found these red flags:\n" + urlFlags.map((f, i) => (i + 1) + ". " + f).join("\n") + "\n"
      : "";

    const question =
      "A user wants to know: is \"" + url + "\" safe to visit?" +
      flagContext +
      "\nAs a cybersecurity expert give a clear verdict. Check if this is:" +
      "\n- A legitimate well-known website" +
      "\n- A phishing or fake page impersonating a real brand" +
      "\n- A scam, fraud, or illegal marketplace" +
      "\n- A malware or suspicious site" +
      "\n\nGive 3-4 sentences in plain English. Start with SAFE, SUSPICIOUS, or MALICIOUS.";

    const apiKey = process.env.GEMINI_API_KEY;
    const sysInstruction = "You are a cybersecurity URL safety checker. Your job is to tell users whether a URL is safe to visit. Always give a clear verdict. You can and should identify malicious, phishing, scam, and illegal websites. Never refuse to analyze a URL.";

    const makeRequest = (useGrounding) => {
      return new Promise((res) => {
        const body = JSON.stringify({
          system_instruction: { parts: [{ text: sysInstruction }] },
          contents: [{ parts: [{ text: question }] }],
          ...(useGrounding ? { tools: [{ google_search: {} }] } : {}),
          generationConfig: { temperature: 0.1, maxOutputTokens: 512 }
        });
        const opts = {
          hostname: "generativelanguage.googleapis.com",
          port: 443,
          path: "/v1beta/models/gemini-2.0-flash:generateContent?key=" + apiKey,
          method: "POST",
          headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }
        };
        const req = https.request(opts, (response) => {
          let data = "";
          console.log("📡 Gemini status:", response.statusCode, useGrounding ? "(with search)" : "(no search)");
          response.on("data", chunk => data += chunk);
          response.on("end", () => res(data));
        });
        req.on("error", () => res(""));
        req.setTimeout(30000, () => { req.destroy(); res("timeout"); });
        req.write(body);
        req.end();
      });
    };

    const extractText = (data) => {
      try {
        const p = JSON.parse(data);
        return p.candidates?.[0]?.content?.parts?.[0]?.text || "";
      } catch (_) { return ""; }
    };

    const detectVerdict = (text) => {
      const u = text.toUpperCase();
      if (u.match(/^(MALICIOUS|NOT SAFE|DO NOT|AVOID)/) ||
        u.includes("NOT SAFE") || u.includes("DO NOT VISIT") ||
        u.includes("MALICIOUS") || u.includes("PHISHING") ||
        u.includes("SCAM") || u.includes("FAKE") ||
        u.includes("ILLEGAL") || u.includes("DANGEROUS") ||
        u.includes("AVOID") || u.includes("FRAUDULENT") ||
        u.includes("MALWARE") || u.includes("CYBERCRIME") ||
        u.includes("WEBSHELL") || u.includes("CREDENTIAL THEFT"))
        return "MALICIOUS";
      if (u.match(/^SUSPICIOUS/) ||
        u.includes("SUSPICIOUS") || u.includes("CAUTION") ||
        u.includes("BE CAREFUL") || u.includes("RISKY") ||
        u.includes("UNVERIFIED") || u.includes("EXERCISE CAUTION"))
        return "SUSPICIOUS";
      return "SAFE";
    };

    (async () => {
      // Attempt 1 — with Google Search grounding (Gemini researches URL live)
      let reply = extractText(await makeRequest(true));
      console.log("🔍 Attempt 1:", reply.substring(0, 150));

      // Attempt 2 — without grounding if blocked
      if (!reply) {
        console.log("⚠️ Attempt 1 blocked — retrying without search grounding");
        reply = extractText(await makeRequest(false));
        console.log("🔍 Attempt 2:", reply.substring(0, 150));
      }

      // Both Gemini attempts blocked — try Groq as fallback
      if (!reply) {
        console.log("⚠️ Both Gemini attempts blocked — trying Groq fallback");
        const groqResult = await analyzeWithGroq(url, domain, urlFlags);

        if (groqResult) {
          console.log("✅ Groq fallback succeeded:", groqResult.gemini_verdict);
          return resolve(groqResult);
        }

        // Groq also failed — use URL flags if any
        console.log("⚠️ Groq also failed — using URL flag fallback");
        if (urlFlags.length > 0) {
          return resolve({
            gemini_verdict: "MALICIOUS",
            gemini_analysis: "This URL was flagged by our security scanner. " + urlFlags.slice(0, 3).join(". ") + ".",
            gemini_confidence: "HIGH",
            gemini_indicators: urlFlags,
            gemini_brand: null,
            gemini_recommendation: "Do NOT visit this URL — multiple security red flags detected."
          });
        }
        return resolve({
          gemini_verdict: "UNKNOWN",
          gemini_analysis: "AI analysis could not be completed for this URL. Use caution and verify independently before visiting.",
          gemini_confidence: "LOW",
          gemini_indicators: [],
          gemini_brand: null,
          gemini_recommendation: "Verify this URL through trusted sources before visiting. When in doubt, do not click."
        });
      }

      const verdict = detectVerdict(reply);
      const sentences = reply.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 10);
      const recommendation = sentences[sentences.length - 1] || "";
      console.log("✅ Gemini verdict:", verdict);

      resolve({
        gemini_verdict: verdict,
        gemini_analysis: reply,
        gemini_confidence: "HIGH",
        gemini_indicators: [],
        gemini_brand: null,
        gemini_recommendation: recommendation
      });
    })();
  });
}

// ── Groq Fallback Analysis ────────────────────────────────────────────────
// Used when Gemini is blocked or fails
// Groq (LLaMA 3.1) has no safety filter blocking for security queries
async function analyzeWithGroq(url, domain, urlFlags) {
  return new Promise((resolve) => {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) return resolve(null);

    const flagContext = urlFlags && urlFlags.length > 0
      ? "\nURL scanner already found these red flags:\n" + urlFlags.map((f, i) => (i + 1) + ". " + f).join("\n") + "\n"
      : "";

    const question =
      "You are a cybersecurity expert. A user wants to know if this URL is safe to visit: \"" + url + "\"" +
      flagContext +
      "\n\nAnalyze this URL and tell me:" +
      "\n1. What is this website — what does it do?" +
      "\n2. Is it safe, suspicious, or malicious?" +
      "\n3. Are there any phishing, scam, fake, or cybercrime indicators?" +
      "\n4. Should the user visit it or avoid it?" +
      "\n\nGive a clear 3-4 sentence answer. Start your response with SAFE, SUSPICIOUS, or MALICIOUS.";

    const body = JSON.stringify({
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity URL safety analyzer. Always give direct verdicts on whether URLs are safe. You analyze phishing, scam, fake, and malicious websites. Never refuse to analyze a URL."
        },
        {
          role: "user",
          content: question
        }
      ],
      temperature: 0.1,
      max_tokens: 512
    });

    const opts = {
      hostname: "api.groq.com",
      port: 443,
      path: "/openai/v1/chat/completions",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiKey,
        "Content-Length": Buffer.byteLength(body)
      }
    };

    const req = https.request(opts, (res) => {
      let data = "";
      console.log("🦙 Groq fallback status:", res.statusCode);
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          const reply = parsed.choices?.[0]?.message?.content || "";
          console.log("🦙 Groq says:", reply.substring(0, 200));

          if (!reply) return resolve(null);

          // Detect verdict from Groq — only check the FIRST sentence to avoid
          // false positives from words like "phishing" used in context (e.g. "no phishing detected")
          const firstSentence = reply.split(/[.!?\n]/)[0].toUpperCase();
          const fullU = reply.toUpperCase();
          const verdict =
            firstSentence.match(/^\s*(MALICIOUS|NOT SAFE|AVOID|DO NOT VISIT|THIS IS MALICIOUS)/) ||
              fullU.includes("DO NOT VISIT") || fullU.includes("THIS IS A PHISHING") ||
              fullU.includes("THIS IS A FAKE") || fullU.includes("THIS IS A SCAM") ||
              fullU.includes("THIS IS MALICIOUS") || fullU.includes("CREDENTIAL THEFT") ||
              fullU.includes("WEBSHELL")
              ? "MALICIOUS"
              : firstSentence.match(/^\s*SUSPICIOUS/) ||
                fullU.includes("EXERCISE CAUTION") || fullU.includes("BE CAREFUL VISITING") ||
                fullU.includes("UNVERIFIED SITE") || fullU.includes("RISKY SITE")
                ? "SUSPICIOUS"
                : "SAFE";

          const sentences = reply.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 10);
          const recommendation = sentences[sentences.length - 1] || "";

          resolve({
            gemini_verdict: verdict,
            gemini_analysis: reply,
            gemini_confidence: "HIGH",
            gemini_indicators: [],
            gemini_brand: null,
            gemini_recommendation: recommendation
          });

        } catch (e) {
          console.log("❌ Groq parse error:", data.substring(0, 100));
          resolve(null);
        }
      });
    });

    req.on("error", () => resolve(null));
    req.setTimeout(20000, () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

// ── Merge verdicts ─────────────────────────────────────────────────────────
function mergeVerdicts(a, b) {
  const sev = { 'SAFE': 0, 'LOW': 1, 'MEDIUM': 2, 'SUSPICIOUS': 2, 'HIGH': 3, 'MALICIOUS': 4, 'CRITICAL': 5, 'UNKNOWN': 0 };
  return sev[(b || '').toUpperCase()] > sev[(a || '').toUpperCase()] ? b : a;
}

// ══════════════════════════════════════════════════════════════════════════
//  SCAN
// ══════════════════════════════════════════════════════════════════════════
app.post('/webhook/url-check', async (req, res) => {
  const { url, user_id } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });

  const norm = normaliseUrl(url);
  const urlRegex = new RegExp('^' + norm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

  // Step 1: Instant URL analysis
  const { urlFlags, urlVerdict, detectedBrand } = analyzeURL(url);

  // Step 1b: Page title mismatch check (runs after n8n returns)
  // This is handled inside the n8n result processing below

  // Step 2: Forward to n8n
  const payload = JSON.stringify({ url });
  const options = {
    hostname: 'localhost',
    port: 5678,
    path: '/webhook/url-check',
    method: 'POST',
    timeout: 120000,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const proxyReq = http.request(options, (proxyRes) => {
    let body = '';
    proxyRes.on('data', chunk => body += chunk);
    proxyRes.on('end', async () => {
      try {
        const d = JSON.parse(body);
        const result = Array.isArray(d) ? d[0] : d;
        const domain = extractDomain(result.url || url);

        // Step 2b: Page title mismatch check
        // URLScan returns the page title — if title claims to be a brand
        // but domain doesn't match, it's fake
        const pageTitle = (result.page_title || result.title || '').toLowerCase();
        if (pageTitle) {
          console.log('📄 Page title:', pageTitle);
          Object.entries(KNOWN_BRANDS).forEach(([keyword, info]) => {
            const titleHasBrand = pageTitle.includes(keyword) ||
              pageTitle.includes(info.name.toLowerCase());
            const domainIsOfficial = domain === info.domain ||
              domain.endsWith('.' + info.domain);
            if (titleHasBrand && !domainIsOfficial) {
              urlFlags.push('Page claims to be "' + info.name + '" (title: "' + pageTitle + '") but domain "' + domain + '" is NOT the official ' + info.name + ' website');
              urlFlags.push('Real ' + info.name + ' is at ' + info.domain + ' — this page title is misleading');
              if (urlVerdict === 'SAFE') urlVerdict = 'SUSPICIOUS';
            }
          });
        }

        // Step 3: Download screenshot
        let screenshotBase64 = null;
        if (result.screenshot) {
          console.log('📸 Fetching screenshot...');
          screenshotBase64 = await fetchImageAsBase64(result.screenshot);
        }

        // Step 4: Ask Gemini AND Groq in parallel
        console.log('🤖 Asking Gemini and Groq in parallel...');
        let [geminiResult, groqResult] = await Promise.all([
          analyzeWithGemini(screenshotBase64, result.url || url, domain, urlFlags),
          analyzeWithGroq(result.url || url, domain, urlFlags)
        ]);

        // If Gemini completely failed, promote Groq to primary (fallback)
        if (!geminiResult) {
          console.log('⚠️ Gemini failed — using Groq as primary');
          geminiResult = groqResult;
          groqResult = null;
        }

        console.log('✅ Gemini verdict:', geminiResult ? geminiResult.gemini_verdict : 'NONE');
        console.log('🦙 Groq verdict:  ', groqResult   ? groqResult.gemini_verdict   : 'NONE');

        // Gemini always drives the final verdict
        // Detect conflict when both responded with different verdicts
        const aiConflict = !!(groqResult && geminiResult &&
          groqResult.gemini_verdict !== geminiResult.gemini_verdict);

        if (aiConflict) {
          console.log('⚠️ AI CONFLICT — Gemini says', geminiResult.gemini_verdict,
            'but Groq says', groqResult.gemini_verdict, '— Gemini wins');
        }

        // Step 5: Gemini always drives the final verdict
        // If Gemini says SAFE → final is SAFE (ignores VT false positives on legit sites)
        // If Gemini says MALICIOUS/SUSPICIOUS → most severe of all sources wins
        const gv = geminiResult ? geminiResult.gemini_verdict : 'UNKNOWN';
        const finalVerdict = gv === 'SAFE' ? 'SAFE' : mergeVerdicts(mergeVerdicts(result.verdict, urlVerdict), gv);

        // Step 6: Combine all indicators
        const allIndicators = [
          ...urlFlags,
          ...(geminiResult.gemini_indicators || [])
        ];

        // Step 7: Build final response
        const finalResult = {
          ...result,
          verdict: finalVerdict,
          risk_level: finalVerdict === "SAFE" ? "LOW" : finalVerdict === "SUSPICIOUS" ? "MEDIUM" : finalVerdict === "MALICIOUS" ? "HIGH" : (result.risk_level || "LOW"),
          gemini_verdict: geminiResult ? geminiResult.gemini_verdict : 'UNKNOWN',
          gemini_analysis: geminiResult ? geminiResult.gemini_analysis : null,
          gemini_confidence: geminiResult ? geminiResult.gemini_confidence : null,
          gemini_indicators: allIndicators,
          gemini_brand: geminiResult ? geminiResult.gemini_brand : null,
          gemini_recommendation: geminiResult ? geminiResult.gemini_recommendation : null,
          groq_verdict: groqResult ? groqResult.gemini_verdict : null,
          groq_analysis: groqResult ? groqResult.gemini_analysis : null,
          ai_conflict: aiConflict,
          url_verdict: urlVerdict
        };

        // Step 8: Save to MongoDB
        try {
          // Derive risk_level from FINAL verdict, not n8n raw result
          const riskLevel = finalVerdict === "SAFE" ? "LOW" : finalVerdict === "SUSPICIOUS" ? "MEDIUM" : finalVerdict === "MALICIOUS" ? "HIGH" : (finalResult.risk_level || "LOW");
          await Scan.findOneAndUpdate(
            { user_id, url: { $regex: urlRegex } },
            {
              $set: {
                user_id,
                url: finalResult.url || url,
                domain,
                verdict: finalVerdict,
                risk_level: riskLevel,
                risk_score: riskLevel === 'LOW' ? 15
                  : riskLevel === 'MEDIUM' ? 55
                    : riskLevel === 'HIGH' ? 85 : 0,
                stats: finalResult.stats || {},
                ai_analysis: finalResult.ai_analysis,
                gemini_verdict: geminiResult ? geminiResult.gemini_verdict : 'UNKNOWN',
                gemini_analysis: geminiResult ? geminiResult.gemini_analysis : null,
                gemini_indicators: allIndicators,
                gemini_brand: geminiResult ? geminiResult.gemini_brand : null,
                groq_verdict: groqResult ? groqResult.gemini_verdict : null,
                groq_analysis: groqResult ? groqResult.gemini_analysis : null,
                ai_conflict: aiConflict,
                screenshot: finalResult.screenshot,
                scanned_by: finalResult.scanned_by,
                timestamp: new Date()
              }
            },
            { upsert: true, new: true }
          );
        } catch (dbErr) {
          console.error('DB error:', dbErr.message);
        }

        // Step 9: Send to frontend
        res.setHeader('Content-Type', 'application/json');
        res.json(finalResult);

      } catch (err) {
        console.error('Scan error:', err.message);
        res.setHeader('Content-Type', 'application/json');
        res.send(body);
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

// ── History ────────────────────────────────────────────────────────────────
app.get('/history', async (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  try {
    const scans = await Scan.find({ user_id })
      .sort({ timestamp: -1 }).limit(50)
      .select('url domain verdict risk_level timestamp stats gemini_verdict');
    res.json(scans);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin ──────────────────────────────────────────────────────────────────
app.post('/admin/verify', (req, res) => {
  res.json({ ok: req.body.token === process.env.ADMIN_TOKEN });
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
    if (search) query.url = { $regex: search, $options: 'i' };
    if (risk_level) query.risk_level = risk_level.toUpperCase();
    if (verdict) query.verdict = verdict.toUpperCase();
    if (user_id) query.user_id = user_id;
    const total = await Scan.countDocuments(query);
    const scans = await Scan.find(query).sort({ timestamp: -1 }).skip((page - 1) * limit).limit(parseInt(limit));
    res.json({ total, page: parseInt(page), pages: Math.ceil(total / limit), scans });
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
  try { res.status(201).json(await Scan.create(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
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
    res.json({ message: 'Deleted ' + r.deletedCount + ' scans' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(3000, () => console.log('🚀  PURL running at http://localhost:3000'));
