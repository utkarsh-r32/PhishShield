require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { simpleParser } = require('mailparser');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

if (NODE_ENV === 'production' && JWT_SECRET === 'dev-only-change-me') {
  throw new Error('JWT_SECRET must be configured in production');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 }
});

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/api/', apiLimiter);

function hash(buffer, algorithm) { return crypto.createHash(algorithm).update(buffer).digest('hex'); }
function sha256(buffer) { return hash(buffer, 'sha256'); }
function sha1(buffer) { return hash(buffer, 'sha1'); }
function md5(buffer) { return hash(buffer, 'md5'); }

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
}

function setAuthCookie(res, token) {
  res.cookie('phishshield_token', token, {
    httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000, path: '/'
  });
}

function authRequired(req, res, next) {
  try {
    const token = req.cookies.phishshield_token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function adminRequired(req, res, next) {
  if (req.user?.role !== 'ADMIN') return res.status(403).json({ error: 'Administrator role required' });
  next();
}

async function audit(userId, action, req, metadata = {}) {
  try {
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, ip_address, metadata) VALUES ($1,$2,$3,$4)',
      [userId || null, action, req.ip || null, metadata]
    );
  } catch (e) { console.error('Audit log error:', e.message); }
}

function domainOf(value) {
  const m = String(value || '').match(/@([a-zA-Z0-9.-]+)/);
  return m ? m[1].toLowerCase().replace(/>.*$/, '') : '';
}
function isIp(domain) {
  return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(domain);
}

function analyzeParsedEmail(parsed, rawBuffer) {
  const headers = {};
  for (const [key, value] of parsed.headers.entries()) {
    headers[key.toLowerCase()] = typeof value === 'string' ? value : JSON.stringify(value);
  }

  const from = parsed.from?.text || headers.from || 'Unknown Sender';
  const to = parsed.to?.text || headers.to || 'Unknown Recipient';
  const cc = parsed.cc?.text || headers.cc || 'None';
  const subject = parsed.subject || headers.subject || '(No Subject)';
  const date = parsed.date?.toISOString?.() || headers.date || 'Unknown Date';
  const replyTo = parsed.replyTo?.text || headers['reply-to'] || 'Not specified';
  const returnPath = headers['return-path'] || 'Not specified';
  const messageId = parsed.messageId || headers['message-id'] || 'Not specified';
  const authResults = headers['authentication-results'] || headers['received-spf'] || '';

  const fromDomain = domainOf(from);
  const returnPathDomain = domainOf(returnPath);
  const replyToDomain = domainOf(replyTo);
  const authLower = authResults.toLowerCase();

  const spfStatus = authLower.includes('spf=pass') ? 'PASS' : authLower.includes('spf=fail') ? 'FAIL' : authLower.includes('spf=softfail') ? 'SOFTFAIL' : 'UNKNOWN';
  const dkimStatus = authLower.includes('dkim=pass') ? 'PASS' : authLower.includes('dkim=fail') ? 'FAIL' : 'UNKNOWN';
  const dmarcStatus = authLower.includes('dmarc=pass') ? 'PASS' : authLower.includes('dmarc=fail') ? 'FAIL' : 'UNKNOWN';

  const cleanText = String(parsed.text || parsed.html || '').replace(/<[^>]+>/g, ' ');
  const urls = Array.from(new Set((cleanText.match(/https?:\/\/[^\s<>"'\)]+/g) || []))).map(url => {
    let domain = '';
    try { domain = new URL(url).hostname; } catch { domain = 'invalid-url'; }
    const isTyposquat = /paypa1|micros0ft|cornpany|g00gle|sec-login|verify-account|bank-update/i.test(domain);
    const suspiciousTLD = /\.(xyz|top|work|click|tk|gq|ml|club|info)$/i.test(domain);
    return { url, domain, isIP: isIp(domain), isTyposquat, isSuspiciousTLD: suspiciousTLD, riskFlag: isIp(domain) || isTyposquat || suspiciousTLD };
  });

  const attachments = (parsed.attachments || []).map(att => {
    const buffer = Buffer.isBuffer(att.content) ? att.content : Buffer.from(att.content || '');
    const extension = path.extname(att.filename || '').replace('.', '').toLowerCase();
    const dangerous = ['exe','scr','vbs','js','bat','cmd','ps1','jar','iso','xlsm','dll','com','msi'].includes(extension);
    return {
      name: att.filename || 'unnamed', extension,
      size: (buffer.length / 1024).toFixed(1) + ' KB',
      isExecutable: dangerous,
      sha256: sha256(buffer), sha1: sha1(buffer), md5: md5(buffer),
      contentType: att.contentType || 'application/octet-stream'
    };
  });

  const urgentKeywords = ['urgent','suspended','immediately','24 hours','action required','unauthorized','wire transfer','gift card','verify account','frozen','login attempt'];
  const lowerText = cleanText.toLowerCase();
  const detectedKeywords = urgentKeywords.filter(kw => lowerText.includes(kw));

  let score = 0;
  const factors = [];
  const add = (points, category, title, desc) => {
    score += points;
    factors.push({ points, category, title, desc });
  };

  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain)
    add(20, 'Header Mismatch', 'From & Return-Path Domain Mismatch', 'The visible sender domain "' + fromDomain + '" differs from the Return-Path domain "' + returnPathDomain + '".');
  if (fromDomain && replyToDomain && replyToDomain !== 'not specified' && !replyToDomain.includes(fromDomain))
    add(15, 'Header Mismatch', 'Reply-To Address Mismatch', 'Replies go to "' + replyToDomain + '", which differs from the displayed sender domain.');
  if (spfStatus === 'FAIL') add(20, 'Authentication', 'SPF Authentication Failed', 'The Authentication-Results header reports SPF failure.');
  else if (spfStatus === 'SOFTFAIL') add(10, 'Authentication', 'SPF SoftFail', 'The Authentication-Results header reports SPF softfail.');
  if (dkimStatus === 'FAIL') add(15, 'Authentication', 'DKIM Signature Failed', 'The Authentication-Results header reports DKIM failure.');
  if (dmarcStatus === 'FAIL') add(20, 'Authentication', 'DMARC Alignment Failed', 'The Authentication-Results header reports DMARC failure.');
  const typos = urls.filter(u => u.isTyposquat);
  if (typos.length) add(25, 'Suspicious Links', 'Typosquatted / Brand Impersonation Domain', 'Detected lookalike domain(s): ' + typos.map(u => u.domain).join(', ') + '.');
  const ips = urls.filter(u => u.isIP);
  if (ips.length) add(20, 'Suspicious Links', 'Raw IP Address Hyperlink', 'Detected direct IP hyperlink(s): ' + ips.map(u => u.domain).join(', ') + '.');
  if (detectedKeywords.length) add(Math.min(20, detectedKeywords.length * 5), 'Content Analysis', 'Urgent & Pressure Language Triggered', 'Found social-engineering indicators: ' + detectedKeywords.join(', ') + '.');
  const dangerous = attachments.filter(a => a.isExecutable);
  if (dangerous.length) add(30, 'Attachments', 'Potentially Harmful Attachment Extension', 'High-risk attachment(s): ' + dangerous.map(a => a.name).join(', ') + '.');

  const finalScore = Math.min(100, Math.max(0, score));
  const riskCategory = finalScore >= 75 ? 'CRITICAL' : finalScore >= 50 ? 'HIGH RISK' : finalScore >= 25 ? 'SUSPICIOUS' : 'SAFE';

  return {
    id: crypto.randomUUID(), timestamp: new Date().toISOString(), filename: null,
    headers: { from, to, cc, subject, date, replyTo, returnPath, messageId, authResults },
    auth: { spfStatus, dkimStatus, dmarcStatus, fromDomain, returnPathDomain, replyToDomain },
    content: { cleanText: cleanText.slice(0, 50000) },
    urls, attachments,
    scoring: { score: finalScore, riskCategory, factors },
    rawSize: rawBuffer.length
  };
}

async function ensureDatabase() {
  if (!process.env.DATABASE_URL) {
    console.warn('DATABASE_URL is not set. PostgreSQL features are unavailable.');
    return;
  }
  const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
  await pool.query(schema);

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword) {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [adminEmail.toLowerCase()]);
    if (!exists.rowCount) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        'INSERT INTO users (id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5)',
        [crypto.randomUUID(), 'PhishShield Administrator', adminEmail.toLowerCase(), passwordHash, 'ADMIN']
      );
      console.log('Created admin account: ' + adminEmail);
    }
  }
}

app.get('/health', async (req, res) => {
  let database = 'not-configured';
  if (process.env.DATABASE_URL) {
    try { await pool.query('SELECT 1'); database = 'connected'; }
    catch { database = 'error'; }
  }
  res.json({ status: database === 'error' ? 'DEGRADED' : 'HEALTHY', database, timestamp: new Date().toISOString() });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password || !process.env.DATABASE_URL) return res.status(400).json({ error: 'Email, password and database configuration are required.' });
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1 AND is_active=true', [email]);
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Invalid email or password' });
    const user = { id: rows[0].id, name: rows[0].name, email: rows[0].email, role: rows[0].role };
    await pool.query('UPDATE users SET last_login_at=NOW() WHERE id=$1', [user.id]);
    await audit(user.id, 'LOGIN', req);
    setAuthCookie(res, signToken(user));
    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authRequired, async (req, res) => {
  await audit(req.user.sub, 'LOGOUT', req);
  res.clearCookie('phishshield_token', { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax', path: '/' });
  res.json({ success: true });
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  res.json({ user: { id: req.user.sub, name: req.user.name, email: req.user.email, role: req.user.role } });
});

app.get('/api/investigations', authRequired, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,filename,subject,sender,recipient,risk_score,risk_category,result,created_at FROM investigations WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',
    [req.user.sub]
  );
  res.json({ investigations: rows.map(r => ({ ...r.result, id: r.id, filename: r.filename, createdAt: r.created_at })) });
});

async function saveInvestigation(req, result, filename) {
  await pool.query(
    'INSERT INTO investigations (id,user_id,filename,subject,sender,recipient,risk_score,risk_category,result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
    [result.id, req.user.sub, filename, result.headers.subject, result.headers.from, result.headers.to, result.scoring.score, result.scoring.riskCategory, JSON.stringify(result)]
  );
  await audit(req.user.sub, 'ANALYZE_EMAIL', req, { investigationId: result.id, score: result.scoring.score });
}

app.post('/api/v1/analyze-eml', authRequired, upload.single('emailFile'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'emailFile is required' });
    const parsed = await simpleParser(req.file.buffer);
    const result = analyzeParsedEmail(parsed, req.file.buffer);
    result.filename = req.file.originalname;
    await saveInvestigation(req, result, req.file.originalname);
    res.json({ success: true, investigation: result });
  } catch (e) {
    console.error('EML processing error:', e);
    res.status(400).json({ error: 'Failed to parse or analyze the .eml file' });
  }
});

app.post('/api/v1/analyze-text', authRequired, async (req, res) => {
  try {
    const raw = Buffer.from(String(req.body.raw || ''), 'utf8');
    if (!raw.length || raw.length > 10 * 1024 * 1024) return res.status(400).json({ error: 'Email text is empty or exceeds 10MB' });
    const parsed = await simpleParser(raw);
    const result = analyzeParsedEmail(parsed, raw);
    result.filename = 'pasted-email.eml';
    await saveInvestigation(req, result, result.filename);
    res.json({ success: true, investigation: result });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Failed to parse email text' });
  }
});

app.get('/api/admin/users', authRequired, adminRequired, async (req, res) => {
  const { rows } = await pool.query('SELECT id,name,email,role,is_active,created_at,last_login_at FROM users ORDER BY created_at DESC');
  res.json({ users: rows });
});

app.post('/api/admin/users', authRequired, adminRequired, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const role = req.body.role === 'ADMIN' ? 'ADMIN' : 'ANALYST';
    if (!name || !email || password.length < 10) return res.status(400).json({ error: 'Name, email and a password of at least 10 characters are required.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = { id: crypto.randomUUID(), name, email, role };
    await pool.query('INSERT INTO users (id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5)', [user.id,name,email,passwordHash,role]);
    await audit(req.user.sub, 'CREATE_USER', req, { createdUserId: user.id, role });
    res.status(201).json({ user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'A user with that email already exists.' });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.get('/api/intel/domain', authRequired, async (req, res) => {
  const domain = String(req.query.domain || '').trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) return res.status(400).json({ error: 'Valid domain required' });
  const result = { domain, virustotal: null, urlscan: null };

  if (process.env.VIRUSTOTAL_API_KEY) {
    try {
      const r = await fetch('https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(domain), {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, accept: 'application/json' }
      });
      result.virustotal = { status: r.ok ? 'LIVE_API_SUCCESS' : 'API_ERROR', data: await r.json() };
    } catch (e) { result.virustotal = { status: 'API_ERROR', error: e.message }; }
  } else result.virustotal = { status: 'NOT_CONFIGURED' };

  if (process.env.URLSCAN_API_KEY) {
    try {
      const q = encodeURIComponent('domain:' + domain);
      const r = await fetch('https://urlscan.io/api/v1/search/?q=' + q, {
        headers: { 'API-Key': process.env.URLSCAN_API_KEY, accept: 'application/json' }
      });
      result.urlscan = { status: r.ok ? 'LIVE_API_SUCCESS' : 'API_ERROR', data: await r.json() };
    } catch (e) { result.urlscan = { status: 'API_ERROR', error: e.message }; }
  } else result.urlscan = { status: 'NOT_CONFIGURED' };

  await audit(req.user.sub, 'INTEL_LOOKUP', req, { domain });
  res.json(result);
});

app.use(express.static(path.join(__dirname)));
app.get(/.*/, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

ensureDatabase().then(() => {
  app.listen(PORT, HOST, () => console.log('PhishShield server listening on ' + HOST + ':' + PORT));
}).catch(err => {
  console.error('Database initialization failed:', err);
  if (NODE_ENV === 'production') process.exit(1);
  app.listen(PORT, HOST, () => console.log('PhishShield server listening on ' + HOST + ':' + PORT + ' without database'));
});
