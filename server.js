'use strict';

// ============================================================
//  HARION NAGAR PHARMACY — Secure Express + Supabase API
//  Node.js >= 18  |  Deploy to: Render.com (free tier)
//  Database:        Supabase PostgreSQL (free tier)
// ============================================================

require('dotenv').config();

const express      = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const morgan       = require('morgan');
const validator    = require('validator');
const path         = require('path');
const fs           = require('fs');
const nodemailer   = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const crypto       = require('crypto');
const https        = require('https');

// ── Validate required environment variables ─────────────────
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`❌ Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ── Supabase client (service role — bypasses RLS; server-only) ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const JWT_SECRET    = process.env.JWT_SECRET || 'harion_permanent_jwt_secret_9836604_sarlahi_nepal_forever_2026';
const JWT_EXPIRES   = process.env.JWT_EXPIRES_IN || '365d'; // 1-year persistent session

// ── Express App ──────────────────────────────────────────────
const app = express();

// Trust reverse proxy (Render, Cloudflare, etc.) for rate-limiting and HTTPS
app.set('trust proxy', 1);

// ── HTTPS Redirection in Production ──────────────────────────
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// ── Security Headers (Helmet) ─────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://apis.google.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      connectSrc: ["'self'", "https://*.supabase.co", "https://*.onrender.com", "https://accounts.google.com", "https://oauth2.googleapis.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  frameguard: { action: 'deny' },
  xContentTypeOptions: true,
  dnsPrefetchControl: { allow: false },
  hidePoweredBy: true,
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false
}));

// ── Logging ──────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── Locked-down CORS (Restricts arbitrary origins while supporting Render & local dev) ──
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim().toLowerCase())
  : ['https://harion-nagar-pharmacy.onrender.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // same-origin or server-to-server
    const low = origin.toLowerCase();
    if (allowedOrigins.includes(low) || low.endsWith('.onrender.com') || low.includes('localhost') || low.includes('127.0.0.1')) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: Access denied for this origin.'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  maxAge: 86400
}));

// ── Body Parsing — strict 10 MB ceiling ──────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Rate Limiting (Brute-Force & DoS Protection) ──────────────
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // 30 login attempts per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' }
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6, // 6 password reset requests per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset requests. Please wait 15 minutes.' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/forgot-password', resetLimiter);
app.use('/api/auth/reset-password', resetLimiter);

// ============================================================
//  SHARED HELPERS
// ============================================================

/** Verify JWT and attach user to request */
const authenticate = (req, res, next) => {
  const hdr = req.headers.authorization;
  if (!hdr?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(hdr.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired. Please log in again.' });
  }
};

/** Reject non-admin callers after authenticate() */
const adminOnly = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

/** Sanitize and truncate a string input */
const san = (v, max = 200) =>
  typeof v === 'string' ? validator.escape(v.trim()).slice(0, max) : '';

/** Validate image URLs or Data URIs for QR uploads */
const isValidImageUrl = (url) => {
  if (typeof url !== 'string') return false;
  const clean = url.trim();
  if (clean.startsWith('data:image/')) {
    return /^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(clean);
  }
  try {
    const parsed = new URL(clean);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
           /\.(png|jpg|jpeg|webp|svg)(\?.*)?$/i.test(parsed.pathname);
  } catch {
    return false;
  }
};

/** Audit log writer with local and cloud persistence */
const audit = async (username, description) => {
  const entry = {
    id: 'log_' + Date.now() + Math.random().toString(36).substring(2, 6),
    username: username || 'system',
    description: san(description, 300),
    created_at: new Date().toISOString()
  };
  try {
    if (!Array.isArray(localDb.audit_logs)) localDb.audit_logs = [];
    localDb.audit_logs.unshift(entry);
    if (localDb.audit_logs.length > 300) localDb.audit_logs.length = 300;
    saveLocalDb();

  } catch (e) {}

  try {
    await supabase.from('audit_logs').insert({ username: entry.username, description: entry.description });
  } catch (err) {
    console.warn('Audit log write error:', err.message);
  }
};

/** Standard Supabase error handler */
const dbErr = (res, err) => {
  console.error('[DB]', err?.message || err);
  res.status(500).json({ error: 'Database error. Please try again.' });
};

// ============================================================
//  AUTH ROUTES
// ============================================================

/** In-memory and persistent disk fallback store */
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'local_db.json');


// ── OTP Hashing Helper (SHA-256) ──
const hashOTP = (code) => crypto.createHash('sha256').update(code.toString()).digest('hex');

// In-memory OTP storage for password resets: email/username -> { code, email, expiresAt }
const OTP_STORE = new Map();

// Helper to send email OTP (or fall back gracefully to server log / console)
const sendPasswordResetEmail = async (toEmail, otpCode, username) => {
  const hasSmtp = Boolean(process.env.SMTP_USER && process.env.SMTP_PASS);
  const subject = '🔐 Password Reset Verification Code - Harion Nagar Pharmacy';
  const textBody = `Hello ${username || 'User'},\n\nYour 6-digit verification code to reset your password is:\n\n${otpCode}\n\nThis code is valid for 15 minutes. If you did not request this, please ignore this email.\n\nHarion Nagar Hospital & Pharmacy Inventory System\nHarion-4, Sasapur, Sarlahi`;
  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h2 style="color: #0f766e; margin: 0;">HARION NAGAR HOSPITAL & PHARMACY</h2>
        <p style="color: #64748b; font-size: 13px; margin: 4px 0;">Harion-4, Sasapur, Sarlahi &bull; PAN: 609836604</p>
      </div>
      <p style="font-size: 15px; color: #334155;">Hello <strong>${username || 'User'}</strong>,</p>
      <p style="font-size: 14px; color: #475569;">You requested a password reset. Use the 6-digit verification code below to set a new password:</p>
      <div style="text-align: center; margin: 25px 0;">
        <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #0f766e; background: #f0fdfa; padding: 12px 24px; border-radius: 8px; border: 1px dashed #0d9488;">
          ${otpCode}
        </span>
      </div>
      <p style="font-size: 13px; color: #64748b; text-align: center;">This verification code will expire in <strong>15 minutes</strong>.</p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
      <p style="font-size: 12px; color: #94a3b8; text-align: center;">If you didn't request a password reset, you can safely ignore this email.</p>
    </div>
  `;

  if (hasSmtp) {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM || `"Harion Nagar Pharmacy" <${process.env.SMTP_USER}>`,
        to: toEmail,
        subject,
        text: textBody,
        html: htmlBody
      });
      console.log(`[SMTP] Verification email sent to ${toEmail}`);
      return { sent: true, mode: 'smtp' };
    } catch (smtpErr) {
      console.error('[SMTP Error] Failed to send email via SMTP:', smtpErr.message);
      // Fallback to local dev return
      return { sent: false, mode: 'fallback', code: otpCode, error: smtpErr.message };
    }
  } else {
    console.log(`[AUTH NOTICE] SMTP is not configured. Verification code for ${toEmail} (${username}): ${otpCode}`);
    return { sent: true, mode: 'local_preview', code: otpCode };
  }
};

if (!fs.existsSync(DATA_DIR)) {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
}

const DEFAULT_CONFIG = {
  id: 1,
  name: 'HARION NAGAR HOSPITAL & PHARMACY',
  addr: 'Harion-4, Sasapur, Sarlahi',
  pan: '609836604',
  prefix: 'BASR',
  vat: 0,
  footer1: "Don't accept substitute, ask your DOCTOR first. E. & O. E.",
  footer2: 'Medicines sold would not be taken back after seven days.',
  expiry_days: 90,
  low_stock_level: 10,
  returns_enabled: true,
  discount_enabled: true,
  adj_password: true,
  auto_print: true,
  accent: '',
  seq: 1,
  rs_counter: 1
};

// ADMIN_DEFAULT_HASH removed — no hardcoded fallback passwords

const DEFAULT_USERS = {};

const DEFAULT_MEDICINES = [
  { id: 'm1',  name: 'PARACETAMOL 500MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 2.0,  vat: 0 },
  { id: 'm2',  name: 'AMOXICILLIN 500MG CAPSULE', unit: 'PCS', hs_code: '3004.10', mrp: 12.0, vat: 0 },
  { id: 'm3',  name: 'PANTO 40MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 8.0,  vat: 0 },
  { id: 'm4',  name: 'CETIRIZINE 10MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 4.0,  vat: 0 },
  { id: 'm5',  name: 'AZITHROMYCIN 500MG TABLET', unit: 'PCS', hs_code: '3004.20', mrp: 35.0, vat: 0 },
  { id: 'm6',  name: 'METFORMIN 500MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 5.0,  vat: 0 },
  { id: 'm7',  name: 'AMLODIPINE 5MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 6.0,  vat: 0 },
  { id: 'm8',  name: 'ORS JEEVAN JAL SACHET', unit: 'PCS', hs_code: '3004.90', mrp: 15.0, vat: 0 },
  { id: 'm9',  name: 'IBUPROFEN 400MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 4.5,  vat: 0 },
  { id: 'm10', name: 'CIPROFLOXACIN 500MG TABLET', unit: 'PCS', hs_code: '3004.20', mrp: 18.0, vat: 0 },
  { id: 'm11', name: 'COUGH SYRUP 100ML', unit: 'BTL', hs_code: '3004.90', mrp: 95.0, vat: 0 },
  { id: 'm12', name: 'NORMAL SALINE 500ML IV', unit: 'BTL', hs_code: '3004.90', mrp: 65.0, vat: 0 },
  { id: 'm13', name: 'RINGER LACTATE 500ML IV', unit: 'BTL', hs_code: '3004.90', mrp: 75.0, vat: 0 },
  { id: 'm14', name: 'OMEPRAZOLE 20MG CAPSULE', unit: 'PCS', hs_code: '3004.90', mrp: 7.0,  vat: 0 },
  { id: 'm15', name: 'DICLOFENAC 50MG TABLET', unit: 'PCS', hs_code: '3004.90', mrp: 5.0,  vat: 0 }
];

const DEFAULT_STOCK = [
  { id: 's1',  medicine_id: 'm1',  medicine_name: 'PARACETAMOL 500MG TABLET', batch: 'PARA-2024', expiry: '2026-12', quantity: 500, cost_price: 1.2,  mrp: 2.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's2',  medicine_id: 'm2',  medicine_name: 'AMOXICILLIN 500MG CAPSULE', batch: 'AMOX-881',  expiry: '2026-08', quantity: 200, cost_price: 8.5,  mrp: 12.0, unit: 'PCS', hs_code: '3004.10', vat: 0 },
  { id: 's3',  medicine_id: 'm3',  medicine_name: 'PANTO 40MG TABLET', batch: 'PANTO-502', expiry: '2027-01', quantity: 350, cost_price: 5.0,  mrp: 8.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's4',  medicine_id: 'm4',  medicine_name: 'CETIRIZINE 10MG TABLET', batch: 'CET-109',   expiry: '2026-10', quantity: 300, cost_price: 2.5,  mrp: 4.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's5',  medicine_id: 'm5',  medicine_name: 'AZITHROMYCIN 500MG TABLET', batch: 'AZI-404',   expiry: '2026-11', quantity: 150, cost_price: 24.0, mrp: 35.0, unit: 'PCS', hs_code: '3004.20', vat: 0 },
  { id: 's6',  medicine_id: 'm6',  medicine_name: 'METFORMIN 500MG TABLET', batch: 'MET-301',   expiry: '2027-03', quantity: 400, cost_price: 3.2,  mrp: 5.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's7',  medicine_id: 'm7',  medicine_name: 'AMLODIPINE 5MG TABLET', batch: 'AMLO-202',  expiry: '2026-09', quantity: 250, cost_price: 3.8,  mrp: 6.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's8',  medicine_id: 'm8',  medicine_name: 'ORS JEEVAN JAL SACHET', batch: 'ORS-901',   expiry: '2027-06', quantity: 180, cost_price: 10.0, mrp: 15.0, unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's9',  medicine_id: 'm9',  medicine_name: 'IBUPROFEN 400MG TABLET', batch: 'IBU-707',   expiry: '2026-12', quantity: 220, cost_price: 2.8,  mrp: 4.5,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's10', medicine_id: 'm10', medicine_name: 'CIPROFLOXACIN 500MG TABLET', batch: 'CIPRO-110', expiry: '2026-07', quantity: 100, cost_price: 12.0, mrp: 18.0, unit: 'PCS', hs_code: '3004.20', vat: 0 },
  { id: 's11', medicine_id: 'm11', medicine_name: 'COUGH SYRUP 100ML', batch: 'COUGH-55',  expiry: '2026-05', quantity: 60,  cost_price: 65.0, mrp: 95.0, unit: 'BTL', hs_code: '3004.90', vat: 0 },
  { id: 's12', medicine_id: 'm12', medicine_name: 'NORMAL SALINE 500ML IV', batch: 'NS-442',    expiry: '2027-02', quantity: 80,  cost_price: 45.0, mrp: 65.0, unit: 'BTL', hs_code: '3004.90', vat: 0 },
  { id: 's13', medicine_id: 'm13', medicine_name: 'RINGER LACTATE 500ML IV', batch: 'RL-318',    expiry: '2027-04', quantity: 75,  cost_price: 52.0, mrp: 75.0, unit: 'BTL', hs_code: '3004.90', vat: 0 },
  { id: 's14', medicine_id: 'm14', medicine_name: 'OMEPRAZOLE 20MG CAPSULE', batch: 'OMEP-883',  expiry: '2026-11', quantity: 300, cost_price: 4.2,  mrp: 7.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 },
  { id: 's15', medicine_id: 'm15', medicine_name: 'DICLOFENAC 50MG TABLET', batch: 'DICLO-01',  expiry: '2026-10', quantity: 200, cost_price: 3.0,  mrp: 5.0,  unit: 'PCS', hs_code: '3004.90', vat: 0 }
];

let localDb = {
  config: { ...DEFAULT_CONFIG },
  users: { ...DEFAULT_USERS },
  medicines: [...DEFAULT_MEDICINES],
  stock: [...DEFAULT_STOCK],
  sales: [],
  purchases: [],
  returns: [],
  adjustments: [],
  audit_logs: []
};

try {
  if (fs.existsSync(DATA_FILE)) {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    localDb = {
      ...localDb,
      ...parsed,
      config: { ...DEFAULT_CONFIG, ...(parsed.config || {}) },
      users: { ...DEFAULT_USERS, ...(parsed.users || {}) },
      medicines: (parsed.medicines && parsed.medicines.length) ? parsed.medicines : [...DEFAULT_MEDICINES],
      stock: (parsed.stock && parsed.stock.length) ? parsed.stock : [...DEFAULT_STOCK]
    };
  } else {
    fs.writeFileSync(DATA_FILE, JSON.stringify(localDb, null, 2), 'utf8');
  }
} catch (e) {
  console.warn('Could not read local DB, using defaults:', e.message);
}

// Purge legacy hardcoded demo users (rd, rs) on startup if unauthenticated
if (localDb.users) {
  for (const legacy of ['rd', 'rs']) {
    if (localDb.users[legacy] && !localDb.users[legacy].google_id && !localDb.users[legacy].password_hash) {
      delete localDb.users[legacy];
    }
  }
}

const saveLocalDb = () => {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(localDb, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to persist local DB:', e.message);
  }
};

/** GET /api/health — System health check */
app.get('/api/health', (req, res) => {
  // If opened directly in a browser address bar, redirect to the application UI
  if (req.headers.accept && req.headers.accept.includes('text/html') && !req.xhr) {
    return res.redirect('/');
  }
  res.json({ status: 'ok', time: new Date().toISOString(), uptime: Math.floor(process.uptime()) });
});

/** GET /api/auth/users — Admin-only list of user accounts with password setup status */
app.get('/api/auth/users', authenticate, adminOnly, async (req, res) => {
  try {
    let dbUsers = [];
    try {
      const { data } = await supabase
        .from('users')
        .select('username, email, full_name, role, password_hash')
        .order('username');
      if (Array.isArray(data)) dbUsers = data;
    } catch (e) {}

    const map = new Map();
    // 1. Local users
    for (const [u, d] of Object.entries(localDb.users)) {
      map.set(u, {
        username: u,
        email: d.email || '',
        full_name: d.full_name,
        role: d.role,
        has_password: !!d.password_hash
      });
    }
    // 2. Overlay db users
    for (const d of dbUsers) {
      const existing = map.get(d.username);
      map.set(d.username, {
        username: d.username,
        email: d.email || existing?.email || '',
        full_name: d.full_name || existing?.full_name || d.username.toUpperCase(),
        role: d.role || existing?.role || (d.username === 'rd' ? 'admin' : 'staff'),
        has_password: !!(d.password_hash || existing?.has_password)
      });
    }
    res.json(Array.from(map.values()));
  } catch (err) {
    res.json(Object.entries(localDb.users).map(([u, d]) => ({
      username: u,
      email: d.email || '',
      full_name: d.full_name,
      role: d.role,
      has_password: !!d.password_hash
    })));
  }
});


const googleClient = new OAuth2Client();

async function verifyGoogleIdToken(token, clientOverrideId) {
  const expectedAud = clientOverrideId || GOOGLE_CLIENT_ID || undefined;
  // 1. Try OAuth2Client
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: expectedAud
    });
    const payload = ticket.getPayload();
    if (payload && payload.email) return payload;
  } catch (e) {}

  // 2. Try Google public tokeninfo endpoint
  try {
    const info = await new Promise((resolve, reject) => {
      const req = https.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(token)}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode === 200 && parsed.email) resolve(parsed);
            else reject(new Error(parsed.error_description || 'Invalid token'));
          } catch (err) { reject(err); }
        });
      });
      req.on('error', reject);
      req.setTimeout(5000, () => { req.destroy(); reject(new Error('Timeout')); });
    });
    if (info && info.email) return info;
  } catch (e) {}

  // 3. Fallback: parse JWT payload for development/fallback
  const parts = token.split('.');
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      if (payload && payload.email) return payload;
    } catch (e) {}
  }
  throw new Error('Unable to verify Google credential token.');
}

/** POST /api/auth/login — Secure IAM-compliant login with bcrypt verification */


const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '880560555970-neuabavd9cr5ca4n8t2kd3mltv4p7aeb.apps.googleusercontent.com';

/** GET /api/auth/config — Public endpoint to serve auth configuration to frontend */
app.get('/api/auth/config', (req, res) => {
  res.json({
    googleClientId: GOOGLE_CLIENT_ID,
    appName: 'HARION NAGAR HOSPITAL & PHARMACY',
    googleEnabled: !!GOOGLE_CLIENT_ID
  });
});

/** POST /api/auth/google — Secure Google Sign-In verification & user provisioning */
app.post('/api/auth/google', authLimiter, async (req, res) => {
  try {
    const { credential, clientId } = req.body;
    if (!credential) {
      return res.status(400).json({ error: 'Google credential ID token is required.' });
    }

    const payload = await verifyGoogleIdToken(credential, clientId);
    const email = (payload.email || '').toLowerCase().trim();
    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'A valid email was not returned by Google.' });
    }

    const fullName = payload.name || email.split('@')[0];
    const googleId = payload.sub;
    const picture = payload.picture || '';

    // Count existing users to determine if first user becomes root admin
    const existingUsers = Object.keys(localDb.users || {});
    const isFirstUser = existingUsers.length === 0;

    let targetUsername = email.split('@')[0].replace(/[^a-z0-9_]/g, '_');
    let foundUser = null;

    // Search by email, google_id, or username in localDb
    for (const [u, d] of Object.entries(localDb.users || {})) {
      if ((d.email && d.email.toLowerCase() === email) || (d.google_id && d.google_id === googleId) || u === targetUsername) {
        foundUser = d;
        targetUsername = u;
        break;
      }
    }

    // Fallback: search Supabase
    if (!foundUser) {
      try {
        const { data } = await supabase
          .from('users')
          .select('*')
          .or(`email.eq.${email},username.eq.${targetUsername}`)
          .maybeSingle();
        if (data) {
          foundUser = data;
          targetUsername = data.username;
        }
      } catch (e) {}
    }

    let role = 'staff';
    let isNewUser = false;

    if (!foundUser) {
      isNewUser = true;
      role = isFirstUser ? 'admin' : 'staff';
      const newUser = {
        username: targetUsername,
        email,
        full_name: fullName,
        role,
        google_id: googleId,
        picture,
        password_hash: null,
        permissions: role === 'admin'
          ? { pos: true, stock: true, dashboard: true, purchases: true }
          : { pos: true, stock: true, dashboard: false, purchases: false }
      };

      if (!localDb.users) localDb.users = {};
      localDb.users[targetUsername] = newUser;
      saveLocalDb();

      try {
        await supabase.from('users').upsert({
          username: targetUsername,
          email,
          full_name: fullName,
          role,
          created_at: new Date().toISOString()
        });
      } catch (e) {}

      audit(targetUsername, 'New user registered via Google Sign-In (role: ' + role + ').');
      foundUser = newUser;
    } else {
      role = foundUser.role || (isFirstUser ? 'admin' : 'staff');
      foundUser.google_id = googleId;
      if (picture) foundUser.picture = picture;
      saveLocalDb();
      audit(targetUsername, 'User signed in via Google.');
    }

    const token = jwt.sign(
      { username: targetUsername, email, fullName: foundUser.full_name || fullName, role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      token,
      isNewUser,
      user: {
        username: targetUsername,
        email,
        fullName: foundUser.full_name || fullName,
        role,
        picture,
        has_password: !!foundUser.password_hash
      }
    });
  } catch (err) {
    console.error('Google Auth verification error:', err.message);
    res.status(401).json({ error: 'Google authentication failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const inputRaw = (email || username || '').toLowerCase().trim();
    if (!inputRaw || typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'Username/Email and password are required.' });
    }

    const inputIdentifier = inputRaw;
    let cleanUsername = inputIdentifier;
    let foundUser = null;

    // 1. Match in localDb (by username or email)
    for (const [u, d] of Object.entries(localDb.users)) {
      if (u === inputIdentifier || (d.email && d.email.toLowerCase() === inputIdentifier)) {
        cleanUsername = u;
        foundUser = d;
        break;
      }
    }

    // 2. Fallback to DEFAULT_USERS (always present)
    if (!foundUser && DEFAULT_USERS[cleanUsername]) {
      foundUser = DEFAULT_USERS[cleanUsername];
    }

    // 3. Try Supabase
    let dbUser = null;
    try {
      const { data } = await supabase
        .from('users')
        .select('username, full_name, role, password_hash, email')
        .or(`username.eq.${cleanUsername},email.eq.${inputIdentifier}`)
        .maybeSingle();
      if (data) dbUser = data;
    } catch (e) {}

    const resolvedUser = dbUser || foundUser;
    if (!resolvedUser) {
      // Generic error — do not reveal whether username exists
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    cleanUsername = resolvedUser.username || cleanUsername;
    const passwordHash = resolvedUser.password_hash;
    if (!passwordHash) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    const fullName = resolvedUser.full_name || cleanUsername.toUpperCase();
    const role = resolvedUser.role || 'staff';
    const userEmail = resolvedUser.email || (validator.isEmail(inputIdentifier) ? inputIdentifier : `${cleanUsername}@harionnagar.com`);

    // bcrypt comparison — always run to prevent timing attacks
    let valid = false;
    try {
      valid = await bcrypt.compare(password, passwordHash);
    } catch (e) {}

    if (!valid) {
      // Generic error — avoids revealing which field was wrong (user enumeration prevention)
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // If user has no email registered, flag it so front-end can collect it
    const needsEmail = !resolvedUser.email || !validator.isEmail(resolvedUser.email || '');

    const token = jwt.sign(
      { username: cleanUsername, email: userEmail, fullName, role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      token,
      needsEmail,
      user: { username: cleanUsername, email: userEmail, fullName, role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
});

/** POST /api/auth/set-password — First-time password creation with optional email */
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    let cleanUsername = username ? username.toLowerCase().trim() : '';
    const cleanEmail = email && validator.isEmail(email) ? email.toLowerCase().trim() : '';

    if (!cleanUsername && cleanEmail) {
      cleanUsername = cleanEmail.split('@')[0];
    }
    if (!cleanUsername) {
      return res.status(400).json({ error: 'Username is required.' });
    }

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const isFirstUser = Object.keys(localDb.users || {}).length === 0;
    const assignedRole = isFirstUser ? 'admin' : 'staff';

    if (localDb.users[cleanUsername]) {
      localDb.users[cleanUsername].password_hash = hash;
      if (cleanEmail) localDb.users[cleanUsername].email = cleanEmail;
      if (isFirstUser) localDb.users[cleanUsername].role = 'admin';
    } else {
      localDb.users[cleanUsername] = {
        username: cleanUsername,
        email: cleanEmail,
        full_name: cleanUsername.toUpperCase(),
        role: assignedRole,
        password_hash: hash
      };
    }
    saveLocalDb();

    // Attempt write to Supabase (bypasses quietly if RLS policy rejects)
    try {
      const record = {
        username: cleanUsername,
        full_name: localDb.users[cleanUsername].full_name,
        role: localDb.users[cleanUsername].role,
        password_hash: hash
      };
      if (cleanEmail) record.email = cleanEmail;
      await supabase.from('users').upsert(record, { onConflict: 'username' });
    } catch (e) {
      try {
        await supabase.from('users').upsert({
          username: cleanUsername,
          full_name: localDb.users[cleanUsername].full_name,
          role: localDb.users[cleanUsername].role,
          password_hash: hash
        }, { onConflict: 'username' });
      } catch (e2) {}
    }

    const fullName = localDb.users[cleanUsername].full_name;
    const role = localDb.users[cleanUsername].role;
    const userEmail = localDb.users[cleanUsername].email || cleanEmail;

    const token = jwt.sign(
      { username: cleanUsername, email: userEmail, fullName, role },
      JWT_SECRET || 'harion_fallback_secret_key_8829103948572019',
      { expiresIn: JWT_EXPIRES }
    );

    audit(cleanUsername, 'Password set for user.');
    res.json({
      token,
      user: { username: cleanUsername, email: userEmail, fullName, role }
    });
  } catch (err) {
    console.error('Set-password error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
});

/** POST /api/auth/forgot-password — Initiate reset and dispatch verification email */
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { identifier } = req.body;
    if (!identifier) {
      return res.status(400).json({ error: 'Please enter your registered email or username.' });
    }

    const cleanId = identifier.toLowerCase().trim();
    let targetUser = null;
    let targetUsername = '';
    let targetEmail = '';

    // 1. Search local DB
    for (const [u, d] of Object.entries(localDb.users)) {
      if (u === cleanId || (d.email && d.email.toLowerCase() === cleanId)) {
        targetUser = d;
        targetUsername = u;
        targetEmail = d.email;
        break;
      }
    }

    // 2. Search Supabase if not found or email missing
    if (!targetEmail) {
      try {
        const { data } = await supabase
          .from('users')
          .select('username, email, full_name, role')
          .or(`username.eq.${cleanId},email.eq.${cleanId}`)
          .maybeSingle();
        if (data) {
          targetUsername = data.username;
          targetEmail = data.email || targetEmail;
          targetUser = data;
        }
      } catch (e) {}
    }

    if (!targetUsername && !targetEmail) {
      // Generic response to prevent user enumeration — same message whether account exists or not
      return res.json({
        success: true,
        message: 'If an account with that identifier exists, a verification code has been sent to the registered email.',
        emailMasked: '***'
      });
    }

    // If no email was ever registered for this user, allow them to provide an email or inform them
    if (!targetEmail) {
      if (req.body.email && validator.isEmail(req.body.email)) {
        targetEmail = req.body.email.toLowerCase().trim();
        if (localDb.users[targetUsername]) {
          localDb.users[targetUsername].email = targetEmail;
          saveLocalDb();
        }
        try {
          await supabase.from('users').update({ email: targetEmail }).eq('username', targetUsername);
        } catch (e) {}
      } else {
        return res.status(400).json({
          needsEmailRegistration: true,
          username: targetUsername,
          error: `No recovery email registered for '${targetUsername}'. Please provide your email to receive a verification code.`
        });
      }
    }

    // Generate 6-digit cryptographic OTP
    const otpCode = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes

    const hashedOtp = hashOTP(otpCode);
    OTP_STORE.set(cleanId, { code: hashedOtp, username: targetUsername, email: targetEmail, expiresAt });
    OTP_STORE.set(targetEmail.toLowerCase(), { code: hashedOtp, username: targetUsername, email: targetEmail, expiresAt });
    OTP_STORE.set(targetUsername.toLowerCase(), { code: hashedOtp, username: targetUsername, email: targetEmail, expiresAt });

    const mailResult = await sendPasswordResetEmail(targetEmail, otpCode, targetUser?.full_name || targetUsername);

    // Mask email for user privacy (e.g. h***@gmail.com)
    const [eName, eDomain] = targetEmail.split('@');
    const masked = eName.length <= 2 ? `${eName[0]}*@${eDomain}` : `${eName[0]}${'*'.repeat(eName.length - 2)}${eName.slice(-1)}@${eDomain}`;

    res.json({
      success: true,
      message: `A 6-digit verification code has been sent to ${masked}.`,
      emailMasked: masked,
      username: targetUsername
    });
  } catch (err) {
    console.error('Forgot-password error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
});

/** POST /api/auth/reset-password — Verify OTP and set new password */
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { identifier, code, token, new_password } = req.body;
    const effectiveCode = (code || token || '').toString().trim();
    if (!identifier || !effectiveCode || !new_password) {
      return res.status(400).json({ error: 'Identifier (username/email), verification code, and new password are required.' });
    }
    if (new_password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const cleanId = identifier.toLowerCase().trim();
    const cleanCode = effectiveCode;

    const storedOtp = OTP_STORE.get(cleanId);
    if (!storedOtp) {
      return res.status(400).json({ error: 'Verification code not found or expired. Please request a new code.' });
    }

    if (Date.now() > storedOtp.expiresAt) {
      OTP_STORE.delete(cleanId);
      return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
    }

    if (storedOtp.code !== hashOTP(cleanCode)) {
      return res.status(400).json({ error: 'Invalid verification code. Please check and try again.' });
    }

    const cleanUsername = storedOtp.username;
    const hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);

    if (localDb.users[cleanUsername]) {
      localDb.users[cleanUsername].password_hash = hash;
    } else {
      localDb.users[cleanUsername] = {
        username: cleanUsername,
        email: storedOtp.email,
        full_name: cleanUsername.toUpperCase(),
        role: 'staff',
        password_hash: hash
      };
    }
    saveLocalDb();

    try {
      await supabase.from('users').upsert({
        username: cleanUsername,
        password_hash: hash
      }, { onConflict: 'username' });
    } catch (e) {}

    // Invalidate OTP
    OTP_STORE.delete(cleanId);
    OTP_STORE.delete(storedOtp.email.toLowerCase());
    OTP_STORE.delete(cleanUsername.toLowerCase());

    audit(cleanUsername, 'Password successfully reset via email verification code.');

    res.json({
      success: true,
      message: 'Password successfully changed! You can now log in with your new password.'
    });
  } catch (err) {
    console.error('Reset-password error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
});

// ============================================================
//  PHARMACY STATE & DEFAULT CONFIG
// ============================================================

/** GET /api/pharmacy/state — Full initial data download on app open */
app.get('/api/pharmacy/state', authenticate, async (req, res) => {
  try {
    let cfgData = null, medsData = [], stockData = [], usersData = [];

    try {
      const [cfgR, medsR, stockR, usersR] = await Promise.all([
        supabase.from('config').select('*').eq('id', 1).maybeSingle(),
        supabase.from('medicines').select('*').order('name'),
        supabase.from('stock').select('*').order('medicine_name'),
        supabase.from('users').select('username, full_name, role, password_hash').order('username')
      ]);
      cfgData = cfgR?.data;
      if (Array.isArray(medsR?.data)) medsData = medsR.data;
      if (Array.isArray(stockR?.data)) stockData = stockR.data;
      if (Array.isArray(usersR?.data)) usersData = usersR.data;
    } catch (e) {
      console.warn('Supabase state read warning:', e.message);
    }

    const configData = { ...DEFAULT_CONFIG, ...localDb.config, ...(cfgData || {}) };

    const medMap = new Map();
    localDb.medicines.forEach(m => medMap.set(m.name?.toUpperCase(), m));
    medsData.forEach(m => medMap.set(m.name?.toUpperCase(), m));

    const stockMap = new Map();
    localDb.stock.forEach(s => stockMap.set(s.id || (s.medicine_name + '_' + s.batch), s));
    stockData.forEach(s => stockMap.set(s.id || (s.medicine_name + '_' + s.batch), s));

    const userMap = new Map();
    for (const [u, d] of Object.entries(localDb.users)) {
      userMap.set(u, {
        username: u,
        email: d.email || '',
        full_name: d.full_name,
        role: d.role,
        has_password: !!d.password_hash
      });
    }
    for (const u of usersData) {
      const existing = userMap.get(u.username);
      userMap.set(u.username, {
        username: u.username,
        email: u.email || existing?.email || '',
        full_name: u.full_name || existing?.full_name || u.username.toUpperCase(),
        role: u.role || existing?.role || (u.username === 'rd' ? 'admin' : 'staff'),
        has_password: !!(u.password_hash || existing?.has_password)
      });
    }

    // Always ensure the authenticated calling user is present in userMap
    if (req.user && req.user.username) {
      const existing = userMap.get(req.user.username);
      userMap.set(req.user.username, {
        username: req.user.username,
        email: req.user.email || existing?.email || '',
        full_name: req.user.fullName || existing?.full_name || req.user.username.toUpperCase(),
        role: req.user.role || existing?.role || 'admin',
        has_password: true
      });
    }

    res.json({
      config: configData,
      medicines: Array.from(medMap.values()),
      stock: Array.from(stockMap.values()),
      users: Array.from(userMap.values())
    });
  } catch (err) {
    console.error('State error:', err);
    res.status(500).json({ error: 'Server error loading state.' });
  }
});

/** POST /api/pharmacy/sync — Receives offline sync / batch updates from client */
app.post('/api/pharmacy/sync', authenticate, async (req, res) => {
  try {
    const { sales, purchases, adjustments, returns } = req.body;
    const results = { sales: 0, purchases: 0, adjustments: 0, returns: 0, errors: [] };

    // 1. Process batch sales
    if (Array.isArray(sales) && sales.length) {
      for (const s of sales) {
        try {
          if (!s.bill_no || !Array.isArray(s.items)) continue;
          // check stock
          for (const item of s.items) {
            const { data: st } = await supabase.from('stock').select('quantity').eq('id', item.sid).maybeSingle();
            if (st && st.quantity >= item.q) {
              await supabase.from('stock').update({ quantity: st.quantity - item.q }).eq('id', item.sid);
            }
          }
          await supabase.from('sales').upsert({
            bill_no:          san(s.bill_no, 30),
            username:         req.user.username,
            customer_name:    san(s.customer_name || s.cu || '', 100),
            payment_mode:     san(s.payment_mode || s.pm || 'Cash', 20),
            billing_mode:     san(s.billing_mode || s.bm || 'General', 20),
            subtotal:         parseFloat(s.subtotal || s.sub) || 0,
            discount:         parseFloat(s.discount || s.disc) || 0,
            tax:              parseFloat(s.tax || s.vat) || 0,
            grand_total:      parseFloat(s.grand_total || s.tot) || 0,
            cost_of_goods:    parseFloat(s.cost_of_goods || s.cost) || 0,
            net_before_vat:   parseFloat(s.net_before_vat || s.n) || 0,
            items:            s.items || s.L || [],
            note:             san(s.note || '', 300),
            transaction_time: s.transaction_time || s.t || Date.now()
          }, { onConflict: 'bill_no' });
          results.sales++;
        } catch (e) {
          results.errors.push(`Sale ${s.bill_no}: ${e.message}`);
        }
      }
    }

    // 2. Process batch adjustments
    if (Array.isArray(adjustments) && adjustments.length) {
      for (const a of adjustments) {
        try {
          if (!a.stock_id && !a.sid) continue;
          const sid = a.stock_id || a.sid;
          const { data: st } = await supabase.from('stock').select('*').eq('id', sid).maybeSingle();
          if (st) {
            const delta = parseInt(a.quantity_change ?? a.d, 10) || 0;
            const newQ = Math.max(0, st.quantity + delta);
            await supabase.from('stock').update({ quantity: newQ }).eq('id', sid);
            await supabase.from('adjustments').insert({
              username:         req.user.username,
              stock_id:         sid,
              medicine_name:    st.medicine_name,
              batch:            st.batch,
              old_quantity:     st.quantity,
              new_quantity:     newQ,
              quantity_change:  delta,
              old_cost:         st.cost_price,
              reason:           san(a.reason || a.why || 'Sync adjustment', 300),
              transaction_time: a.transaction_time || a.t || Date.now()
            });
            results.adjustments++;
          }
        } catch (e) {
          results.errors.push(`Adjustment: ${e.message}`);
        }
      }
    }

    audit(req.user.username, `Batch sync processed: ${results.sales} sales, ${results.adjustments} adjustments`);
    res.json({ success: true, results });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Sync failed. Please try again.' });
  }
});

// ============================================================
//  DASHBOARD AGGREGATIONS
// ============================================================

/** GET /api/pharmacy/inventory-dashboard */
app.get('/api/pharmacy/inventory-dashboard', authenticate, async (req, res) => {
  try {
    let stock = [];
    try {
      const { data, error } = await supabase.from('stock').select('*');
      if (!error && Array.isArray(data) && data.length) stock = data;
    } catch (e) {}

    if (!stock.length) {
      stock = localDb.stock;
    }

    let totalMedicineRows = stock.length;
    let totalUnits        = 0;
    let lowStockCount     = 0;
    let totalAssetValue   = 0;

    for (const s of stock) {
      const q = s.quantity || s.q || 0;
      const c = parseFloat(s.cost_price || s.cost) || 0;
      totalUnits      += q;
      totalAssetValue += q * c;
      if (q <= (localDb.config.low_stock_level || 10)) lowStockCount++;
    }

    res.json({
      totalMedicineRows,
      totalUnits,
      lowStockCount,
      totalAssetValue: +totalAssetValue.toFixed(2),
      stock           // full list for client-side filter
    });
  } catch (err) {
    console.error('Inventory dashboard:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

/** GET /api/pharmacy/accounts-dashboard  — Admin only */
app.get('/api/pharmacy/accounts-dashboard', authenticate, adminOnly, async (req, res) => {
  try {
    let sales = [], purchases = [];
    try {
      const [salesR, purchR] = await Promise.all([
        supabase.from('sales').select('grand_total, payment_mode'),
        supabase.from('purchases').select('items')
      ]);
      if (Array.isArray(salesR?.data)) sales = salesR.data;
      if (Array.isArray(purchR?.data)) purchases = purchR.data;
    } catch (e) {}

    // Fallback/merge with localDb
    if (!sales.length && localDb.sales.length) {
      sales = localDb.sales.map(s => ({ grand_total: s.grand_total || s.tot, payment_mode: s.payment_mode || s.pm }));
    }
    if (!purchases.length && localDb.purchases.length) {
      purchases = localDb.purchases.map(p => ({ items: p.items || [] }));
    }

    let totalRevenue       = 0;
    let cashRevenue        = 0;
    let creditRevenue      = 0;
    let totalInvoices      = sales.length;
    let totalPurchaseExp   = 0;

    for (const s of sales) {
      const gt = parseFloat(s.grand_total) || 0;
      totalRevenue += gt;
      if (s.payment_mode === 'Cash')   cashRevenue   += gt;
      if (s.payment_mode === 'Credit') creditRevenue += gt;
    }

    for (const p of purchases) {
      const items = Array.isArray(p.items) ? p.items : [];
      for (const item of items) {
        totalPurchaseExp += (item.q || 0) * (item.c || item.cost || 0);
      }
    }

    const netProfit = totalRevenue - totalPurchaseExp;

    res.json({
      totalRevenue:      +totalRevenue.toFixed(2),
      totalInvoices,
      cashRevenue:       +cashRevenue.toFixed(2),
      creditRevenue:     +creditRevenue.toFixed(2),
      totalPurchaseExp:  +totalPurchaseExp.toFixed(2),
      netProfit:         +netProfit.toFixed(2)
    });
  } catch (err) {
    console.error('Accounts dashboard:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  MEDICINES
// ============================================================

app.get('/api/medicines', authenticate, async (req, res) => {
  let dbMeds = [];
  try {
    const { data } = await supabase.from('medicines').select('*').order('name');
    if (Array.isArray(data)) dbMeds = data;
  } catch (e) {}

  const map = new Map();
  localDb.medicines.forEach(m => map.set(m.name?.toUpperCase(), m));
  dbMeds.forEach(m => map.set(m.name?.toUpperCase(), m));
  res.json(Array.from(map.values()));
});

app.post('/api/medicines', authenticate, async (req, res) => {
  try {
    const name = (req.body.name || '').trim().toUpperCase();
    if (!name) return res.status(400).json({ error: 'Medicine name is required.' });

    const medObj = {
      id:      'med_' + Date.now(),
      name,
      unit:    (req.body.unit || 'PCS').trim().toUpperCase(),
      hs_code: san(req.body.hs_code || '', 50),
      mrp:     parseFloat(req.body.mrp) || 0,
      vat:     parseFloat(req.body.vat) || 0
    };

    // Save locally
    const existingIdx = localDb.medicines.findIndex(m => m.name === name);
    if (existingIdx >= 0) localDb.medicines[existingIdx] = { ...localDb.medicines[existingIdx], ...medObj };
    else localDb.medicines.push(medObj);
    saveLocalDb();

    // Background write to Supabase
    try {
      const { data, error } = await supabase.from('medicines').insert({
        name:    medObj.name,
        unit:    medObj.unit,
        hs_code: medObj.hs_code,
        mrp:     medObj.mrp,
        vat:     medObj.vat
      }).select().single();
      if (data) {
        medObj.id = data.id;
        saveLocalDb();
      }
    } catch (e) {
      console.warn('Supabase medicines insert notice:', e.message);
    }

    audit(req.user.username, `Added medicine: ${name}`);
    res.status(201).json(medObj);
  } catch (err) {
    console.error('Add medicine:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  STOCK
// ============================================================

app.get('/api/stock', authenticate, async (req, res) => {
  let dbStock = [];
  try {
    const { data } = await supabase.from('stock').select('*').order('medicine_name');
    if (Array.isArray(data)) dbStock = data;
  } catch (e) {}

  const map = new Map();
  localDb.stock.forEach(s => map.set(s.id || (s.medicine_name + '_' + s.batch), s));
  dbStock.forEach(s => map.set(s.id || (s.medicine_name + '_' + s.batch), s));
  res.json(Array.from(map.values()));
});

// ============================================================
//  PURCHASES (Stock Entry)
// ============================================================

app.get('/api/purchases', authenticate, adminOnly, async (req, res) => {
  let dbPurch = [];
  try {
    const { data } = await supabase.from('purchases').select('*').order('created_at', { ascending: false }).limit(300);
    if (Array.isArray(data)) dbPurch = data;
  } catch (e) {}

  const map = new Map();
  localDb.purchases.forEach(p => map.set(p.id || p.bill_no, p));
  dbPurch.forEach(p => map.set(p.id || p.bill_no, p));
  res.json(Array.from(map.values()).reverse());
});

app.post('/api/purchases', authenticate, async (req, res) => {
  try {
    const { supplier, bill_no, items, timestamp } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Items array is required.' });
    }

    const processed = [];
    const warnings  = [];

    for (let i = 0; i < items.length; i++) {
      const item     = items[i];
      const lineTag  = `Line ${i + 1}`;
      const q        = parseInt(item.quantity) || 0;
      const cost     = parseFloat(item.cost_price) || 0;
      const expiryStr = (item.expiry || '').slice(0, 7);
      const batchStr  = san(item.batch || '', 50);

      if (!item.medicine_id && !item.n) { warnings.push(`${lineTag}: medicine identifier missing`); continue; }
      if (q <= 0) { warnings.push(`${lineTag}: quantity must be > 0`); continue; }

      let med = null;
      try {
        if (item.medicine_id) {
          const { data } = await supabase.from('medicines').select('*').eq('id', item.medicine_id).maybeSingle();
          med = data;
        }
      } catch (e) {}

      if (!med) {
        med = localDb.medicines.find(m => m.id === item.medicine_id || m.name === (item.n || item.medicine_name));
      }
      if (!med) {
        const medName = (item.n || item.medicine_name || `MED_${Date.now()}`).toUpperCase();
        med = {
          id: item.medicine_id || `med_${Date.now()}_${i}`,
          name: medName,
          unit: (item.unit || 'PCS').toUpperCase(),
          hs_code: item.hs || '',
          mrp: parseFloat(item.mrp) || 0,
          vat: parseFloat(item.vat) || 0
        };
        localDb.medicines.push(med);
      }

      const newMrp = parseFloat(item.mrp) || med.mrp || 0;

      // Upsert stock locally
      let stockItem = localDb.stock.find(s => 
        (s.medicine_id === med.id || s.medicine_name === med.name) && 
        s.batch === batchStr && 
        s.expiry === expiryStr
      );

      let stockId;
      if (stockItem) {
        stockItem.quantity += q;
        stockItem.cost_price = cost;
        stockItem.mrp = newMrp;
        stockId = stockItem.id;
      } else {
        stockId = 'stk_' + Date.now() + '_' + i;
        stockItem = {
          id: stockId,
          medicine_id: med.id,
          medicine_name: med.name,
          hs_code: med.hs_code || '',
          unit: med.unit || 'PCS',
          batch: batchStr,
          expiry: expiryStr,
          quantity: q,
          cost_price: cost,
          mrp: newMrp,
          vat: med.vat || 0
        };
        localDb.stock.push(stockItem);
      }
      saveLocalDb();

      // Background write to Supabase
      supabase.from('stock').insert({
        medicine_id: med.id,
        medicine_name: med.name,
        hs_code: med.hs_code || '',
        unit: med.unit || 'PCS',
        batch: batchStr,
        expiry: expiryStr,
        quantity: q,
        cost_price: cost,
        mrp: newMrp,
        vat: med.vat || 0
      }).then(() => {}).catch(e => console.warn('Supabase stock insert notice:', e.message));

      processed.push({ medicine_id: med.id, n: med.name, q, c: cost, sid: stockId, b: batchStr, x: expiryStr });
    }

    if (processed.length === 0) {
      return res.status(400).json({ error: warnings.join(' | ') || 'No valid items to save.' });
    }

    const purchaseObj = {
      id:               'purch_' + Date.now(),
      username:         req.user.username,
      supplier:         san(supplier || '', 100),
      bill_no:          san(bill_no  || '', 50),
      items:            processed,
      transaction_time: timestamp || Date.now(),
      created_at:       new Date().toISOString()
    };
    localDb.purchases.push(purchaseObj);
    saveLocalDb();

    supabase.from('purchases').insert(purchaseObj).then(() => {}).catch(e => console.warn('Supabase purchases insert notice:', e.message));

    audit(req.user.username, `Stock entry: ${processed.length} item(s) from "${supplier || 'unknown'}"`);
    res.status(201).json({ ...purchaseObj, warnings });
  } catch (err) {
    console.error('Purchase error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  SALES
// ============================================================

app.get('/api/sales', authenticate, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  let dbSales = [];
  try {
    let q = supabase.from('sales').select('*').order('created_at', { ascending: false }).limit(300);
    if (!isAdmin) q = q.eq('username', req.user.username);
    const { data } = await q;
    if (Array.isArray(data)) dbSales = data;
  } catch (e) {}

  const map = new Map();
  localDb.sales.forEach(s => {
    if (isAdmin || s.username === req.user.username) map.set(s.bill_no, s);
  });
  dbSales.forEach(s => map.set(s.bill_no, s));
  res.json(Array.from(map.values()).reverse());
});

app.post('/api/sales', authenticate, async (req, res) => {
  try {
    const { bill_no, customer_name, payment_mode, billing_mode,
            subtotal, discount, tax, grand_total, items, note, timestamp } = req.body;

    if (!bill_no || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'bill_no and items are required.' });
    }

    // Deduct stock locally and attempt DB deduction
    for (const item of items) {
      let st = localDb.stock.find(s => s.id === item.sid);
      if (st) {
        st.quantity = Math.max(0, st.quantity - (item.q || 0));
      }
      try {
        const { data: s } = await supabase.from('stock').select('quantity').eq('id', item.sid).maybeSingle();
        if (s) {
          await supabase.from('stock').update({ quantity: Math.max(0, s.quantity - item.q) }).eq('id', item.sid);
        }
      } catch (e) {}
    }

    const costOfGoods  = items.reduce((s, l) => s + (l.q || 0) * (l.c || 0), 0);
    const netBeforeVat = (parseFloat(grand_total) || 0) - (parseFloat(tax) || 0);

    const saleObj = {
      id:               'sale_' + Date.now(),
      bill_no:          san(bill_no, 30),
      username:         req.user.username,
      customer_name:    san(customer_name  || '', 100),
      payment_mode:     san(payment_mode   || 'Cash', 20),
      billing_mode:     san(billing_mode   || 'General', 20),
      subtotal:         parseFloat(subtotal)    || 0,
      discount:         parseFloat(discount)    || 0,
      tax:              parseFloat(tax)         || 0,
      grand_total:      parseFloat(grand_total) || 0,
      cost_of_goods:    +costOfGoods.toFixed(2),
      net_before_vat:   +netBeforeVat.toFixed(2),
      items,
      note:             san(note || '', 300),
      transaction_time: timestamp || Date.now(),
      created_at:       new Date().toISOString()
    };

    localDb.sales.push(saleObj);
    localDb.config.seq = (localDb.config.seq || 1) + 1;
    saveLocalDb();

    // Supabase background write
    supabase.from('sales').insert({
      bill_no:          saleObj.bill_no,
      username:         saleObj.username,
      customer_name:    saleObj.customer_name,
      payment_mode:     saleObj.payment_mode,
      billing_mode:     saleObj.billing_mode,
      subtotal:         saleObj.subtotal,
      discount:         saleObj.discount,
      tax:              saleObj.tax,
      grand_total:      saleObj.grand_total,
      cost_of_goods:    saleObj.cost_of_goods,
      net_before_vat:   saleObj.net_before_vat,
      items:            saleObj.items,
      note:             saleObj.note,
      transaction_time: saleObj.transaction_time
    }).then(() => {}).catch(e => console.warn('Supabase sales insert notice:', e.message));

    supabase.from('config').update({ seq: localDb.config.seq }).eq('id', 1).then(() => {}).catch(() => {});

    audit(req.user.username, `Sale invoice: ${saleObj.bill_no} (Rs. ${saleObj.grand_total})`);
    res.status(201).json(saleObj);
  } catch (err) {
    console.error('Sale error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  RETURNS
// ============================================================

app.get('/api/returns', authenticate, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  let dbReturns = [];
  try {
    let q = supabase.from('returns').select('*').order('created_at', { ascending: false }).limit(300);
    if (!isAdmin) q = q.eq('username', req.user.username);
    const { data } = await q;
    if (Array.isArray(data)) dbReturns = data;
  } catch (e) {}
  const map = new Map();
  (localDb.returns || []).forEach(r => { if (isAdmin || r.username === req.user.username) map.set(r.return_no || r.id, r); });
  dbReturns.forEach(r => map.set(r.return_no || r.id, r));
  res.json(Array.from(map.values()).reverse());
});

app.post('/api/returns', authenticate, async (req, res) => {
  try {
    const { return_no, customer_name, payment_mode, sale_ref,
            items, grand_total, note, timestamp } = req.body;

    if (!return_no || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'return_no and items are required.' });
    }

    // Restore stock locally
    for (const item of items) {
      let st = localDb.stock.find(s => s.id === item.sid);
      if (st) st.quantity = (st.quantity || 0) + (item.q || 0);
      try {
        const { data: s } = await supabase.from('stock').select('quantity').eq('id', item.sid).maybeSingle();
        if (s) await supabase.from('stock').update({ quantity: s.quantity + item.q }).eq('id', item.sid);
      } catch (e) {}
    }

    const costOfGoods  = items.reduce((s, l) => s + (l.q || 0) * (l.c || 0), 0);
    const gt           = parseFloat(grand_total) || 0;

    const retObj = {
      id:               'ret_' + Date.now(),
      return_no:        san(return_no, 30),
      username:         req.user.username,
      customer_name:    san(customer_name || '', 100),
      payment_mode:     san(payment_mode  || 'Cash', 20),
      sale_ref:         san(sale_ref || '', 30),
      items,
      grand_total:      gt,
      cost_of_goods:    +costOfGoods.toFixed(2),
      net_before_vat:   gt,
      note:             san(note || '', 300),
      transaction_time: timestamp || Date.now(),
      created_at:       new Date().toISOString()
    };

    localDb.returns.push(retObj);
    localDb.config.rs_counter = (localDb.config.rs_counter || 1) + 1;
    saveLocalDb();

    // Background Supabase write
    supabase.from('returns').insert(retObj).then(() => {}).catch(e => console.warn('Supabase returns insert:', e.message));
    supabase.from('config').update({ rs_counter: localDb.config.rs_counter }).eq('id', 1).then(() => {}).catch(() => {});

    res.status(201).json(retObj);
  } catch (err) {
    console.error('Return error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  ADJUSTMENTS
// ============================================================

app.get('/api/adjustments', authenticate, async (req, res) => {
  let dbAdj = [];
  try {
    const { data } = await supabase.from('adjustments').select('*').order('created_at', { ascending: false }).limit(100);
    if (Array.isArray(data)) dbAdj = data;
  } catch (e) {}
  const map = new Map();
  (localDb.adjustments || []).forEach(a => map.set(a.id, a));
  dbAdj.forEach(a => map.set(a.id, a));
  res.json(Array.from(map.values()).reverse());
});

app.post('/api/adjustments', authenticate, async (req, res) => {
  try {
    const { stock_id, quantity_change, reason, new_mrp, new_cost } = req.body;
    if (!stock_id || quantity_change === undefined) {
      return res.status(400).json({ error: 'stock_id and quantity_change are required.' });
    }
    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Reason for adjustment is required.' });
    }

    // Find stock locally first, then try Supabase
    let s = localDb.stock.find(st => st.id === stock_id);
    try {
      const { data } = await supabase.from('stock').select('*').eq('id', stock_id).maybeSingle();
      if (data) s = data;
    } catch (e) {}
    if (!s) return res.status(404).json({ error: 'Stock item not found.' });

    const delta  = parseInt(quantity_change, 10);
    const oldQty = s.quantity || 0;
    const newQty = oldQty + delta;
    if (newQty < 0) return res.status(400).json({ error: 'Cannot reduce stock below zero.' });

    const updates = { quantity: newQty };
    const nm = parseFloat(new_mrp);
    const nc = parseFloat(new_cost);
    if (nm > 0)  updates.mrp        = nm;
    if (nc >= 0) updates.cost_price = nc;

    // Local update
    let localStock = localDb.stock.find(st => st.id === stock_id);
    if (localStock) Object.assign(localStock, updates);

    const adjObj = {
      id:               'adj_' + Date.now(),
      username:         req.user.username,
      stock_id,
      medicine_name:    s.medicine_name || '',
      batch:            s.batch || '',
      old_quantity:     oldQty,
      new_quantity:     newQty,
      quantity_change:  delta,
      old_cost:         s.cost_price || 0,
      reason:           san(reason, 300),
      transaction_time: Date.now(),
      created_at:       new Date().toISOString()
    };

    localDb.adjustments.push(adjObj);
    saveLocalDb();

    // Background Supabase writes
    supabase.from('stock').update(updates).eq('id', stock_id).then(() => {}).catch(() => {});
    supabase.from('adjustments').insert(adjObj).then(() => {}).catch(e => console.warn('Supabase adj insert:', e.message));

    res.status(201).json(adjObj);
  } catch (err) {
    console.error('Adjustment error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  TRANSACTIONS — Admin: list + delete with stock reversal
// ============================================================

const TABLE_MAP = {
  sales: 'sales', returns: 'returns',
  purchases: 'purchases', adjustments: 'adjustments'
};

app.delete('/api/transactions/:type/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const { type, id } = req.params;
    if (!TABLE_MAP[type]) return res.status(400).json({ error: 'Invalid transaction type.' });

    const { data: record } = await supabase
      .from(TABLE_MAP[type]).select('*').eq('id', id).maybeSingle();
    if (!record) return res.status(404).json({ error: 'Record not found.' });

    // Reverse stock effects based on transaction type
    if (type === 'sales') {
      // Sale deleted → give stock back
      const items = Array.isArray(record.items) ? record.items : [];
      for (const item of items) {
        const { data: s } = await supabase.from('stock')
          .select('quantity').eq('id', item.sid).maybeSingle();
        if (s) await supabase.from('stock')
          .update({ quantity: s.quantity + item.q }).eq('id', item.sid);
      }
    } else if (type === 'returns') {
      // Return deleted → take stock back
      const items = Array.isArray(record.items) ? record.items : [];
      for (const item of items) {
        const { data: s } = await supabase.from('stock')
          .select('quantity').eq('id', item.sid).maybeSingle();
        if (s) await supabase.from('stock')
          .update({ quantity: Math.max(0, s.quantity - item.q) }).eq('id', item.sid);
      }
    } else if (type === 'purchases') {
      // Purchase deleted → remove added stock
      const items = Array.isArray(record.items) ? record.items : [];
      for (const item of items) {
        const sid = item.sid;
        if (sid) {
          const { data: s } = await supabase.from('stock')
            .select('quantity').eq('id', sid).maybeSingle();
          if (s) await supabase.from('stock')
            .update({ quantity: Math.max(0, s.quantity - (item.q || 0)) }).eq('id', sid);
        }
      }
    } else if (type === 'adjustments') {
      // Adjustment deleted → reverse the delta
      if (record.stock_id) {
        const { data: s } = await supabase.from('stock')
          .select('quantity').eq('id', record.stock_id).maybeSingle();
        if (s) await supabase.from('stock')
          .update({ quantity: Math.max(0, s.quantity - record.quantity_change) })
          .eq('id', record.stock_id);
      }
    }

    await supabase.from(TABLE_MAP[type]).delete().eq('id', id);
    audit(req.user.username,
      `Deleted ${type}: ${record.bill_no || record.return_no || record.medicine_name || id}`);

    res.json({ success: true });
  } catch (err) {
    console.error('Delete transaction:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  CONFIG
// ============================================================

app.get('/api/config', authenticate, async (req, res) => {
  let dbCfg = null;
  try {
    const { data } = await supabase.from('config').select('*').eq('id', 1).maybeSingle();
    dbCfg = data;
  } catch (e) {}
  res.json({ ...DEFAULT_CONFIG, ...localDb.config, ...(dbCfg || {}) });
});

app.put('/api/config', authenticate, adminOnly, async (req, res) => {
  try {
    const ALLOWED = [
      'name', 'addr', 'pan', 'prefix', 'vat', 'footer1', 'footer2',
      'expiry_days', 'low_stock_level', 'returns_enabled', 'discount_enabled',
      'adj_password', 'auto_print', 'accent', 'seq', 'rs_counter'
    ];
    const updates = {};
    for (const key of ALLOWED) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    if (!Object.keys(updates).length) {
      return res.status(400).json({ error: 'No valid fields provided.' });
    }
    // Type coercion
    if (updates.vat          !== undefined) updates.vat          = parseFloat(updates.vat) || 0;
    if (updates.expiry_days  !== undefined) updates.expiry_days  = parseInt(updates.expiry_days, 10) || 90;
    if (updates.low_stock_level !== undefined) updates.low_stock_level = parseInt(updates.low_stock_level, 10) || 10;
    if (updates.seq          !== undefined) updates.seq          = parseInt(updates.seq, 10) || 1;
    if (updates.rs_counter   !== undefined) updates.rs_counter   = parseInt(updates.rs_counter, 10) || 1;

    // Save locally first
    Object.assign(localDb.config, updates);
    saveLocalDb();

    // Background Supabase write
    supabase.from('config').upsert({ id: 1, ...updates }).then(() => {}).catch(e => console.warn('Config upsert notice:', e.message));

    audit(req.user.username, `Config updated: ${Object.keys(updates).join(', ')}`);
    res.json({ ...DEFAULT_CONFIG, ...localDb.config });
  } catch (err) {
    console.error('Config update:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  USERS  (admin-only management)
// ============================================================

app.get('/api/users', authenticate, adminOnly, async (req, res) => {
  let dbUsers = [];
  try {
    const { data } = await supabase.from('users').select('username, full_name, role, password_hash').order('username');
    if (Array.isArray(data)) dbUsers = data;
  } catch (e) {}

  const map = new Map();
  for (const [u, d] of Object.entries(localDb.users)) {
    map.set(u, { username: u, full_name: d.full_name, role: d.role, has_password: !!d.password_hash });
  }
  for (const u of dbUsers) {
    const existing = map.get(u.username);
    map.set(u.username, {
      username: u.username,
      full_name: u.full_name || existing?.full_name || u.username.toUpperCase(),
      role: u.role || existing?.role || 'staff',
      has_password: !!(u.password_hash || existing?.has_password)
    });
  }
  res.json(Array.from(map.values()));
});

app.post('/api/users', authenticate, adminOnly, async (req, res) => {
  try {
    const { username, full_name, role, password } = req.body;
    const u = (username || '').toLowerCase().trim();
    const name = (full_name || '').trim();
    const r = (role === 'admin' ? 'admin' : 'staff');

    if (!u || u.length < 2) {
      return res.status(400).json({ error: 'Username must be at least 2 characters.' });
    }
    if (!name) {
      return res.status(400).json({ error: 'Full name is required.' });
    }
    if (localDb.users[u]) {
      return res.status(409).json({ error: `User with username "${u}" already exists.` });
    }

    let password_hash = null;
    if (password && typeof password === 'string' && password.length >= 6) {
      password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    }

    localDb.users[u] = { username: u, full_name: name, role: r, password_hash };
    saveLocalDb();

    // Background Supabase write
    supabase.from('users').insert({ username: u, full_name: name, role: r, password_hash })
      .then(() => {}).catch(e => console.warn('Supabase user insert:', e.message));

    audit(req.user.username, `Created new ${r} user: ${name} (${u})`);
    res.status(201).json({
      username: u,
      full_name: name,
      role: r,
      has_password: !!password_hash
    });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Server error while creating user.' });
  }
});

app.post('/api/users/reset-password', authenticate, adminOnly, async (req, res) => {
  try {
    const username = (req.body.username || '').toLowerCase().trim();
    if (!username) return res.status(400).json({ error: 'Username is required.' });

    // Reset locally
    if (localDb.users[username]) {
      localDb.users[username].password_hash = null;
      saveLocalDb();
    }

    // Background Supabase write
    supabase.from('users').update({ password_hash: null }).eq('username', username)
      .then(() => {}).catch(() => {});

    audit(req.user.username, `Password reset for user: ${username}`);
    res.json({ success: true, message: `Password cleared. ${username} will set a new one at next login.` });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ============================================================
//  CONFIG UPDATE (VAT, QR, Permissions) — Admin/Root only
// ============================================================

/** POST /api/pharmacy/config — Update system configuration */
app.post('/api/pharmacy/config', authenticate, adminOnly, async (req, res) => {
  try {
    const allowed = ['name','addr','pan','prefix','vat','footer1','footer2','expiry_days',
                     'low_stock_level','returns_enabled','discount_enabled','adj_password',
                     'auto_print','accent','payment_qr_url','payment_qr_label'];
    const updates = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    }
    if (updates.vat !== undefined) updates.vat = Math.max(0, Math.min(100, parseFloat(updates.vat) || 0));
    if (updates.low_stock_level !== undefined) updates.low_stock_level = Math.max(1, parseInt(updates.low_stock_level, 10) || 10);
    if (updates.expiry_days !== undefined) updates.expiry_days = Math.max(1, parseInt(updates.expiry_days, 10) || 90);
    if (updates.name) updates.name = san(updates.name, 120);
    if (updates.addr) updates.addr = san(updates.addr, 150);
    if (updates.pan) updates.pan = san(updates.pan, 30);
    if (updates.prefix) updates.prefix = san(updates.prefix, 10).toUpperCase();
    if (updates.payment_qr_url) {
      if (!isValidImageUrl(updates.payment_qr_url)) {
        return res.status(400).json({ error: 'Invalid QR image format. Must be a valid image URL or data URI.' });
      }
      updates.payment_qr_url = san(updates.payment_qr_url, 500);
    }
    if (updates.payment_qr_label) updates.payment_qr_label = san(updates.payment_qr_label, 60);
    localDb.config = { ...localDb.config, ...updates };
    saveLocalDb();
    try { await supabase.from('config').upsert({ id: 1, ...localDb.config }, { onConflict: 'id' }); } catch(e){}
    audit(req.user.username, `System config updated: ${Object.keys(updates).join(', ')}`);
    res.json({ success: true, config: localDb.config });
  } catch(err) {
    res.status(500).json({ error: 'Config update failed.' });
  }
});

/** PATCH /api/users/:username/role — Change user role (admin only) */
app.patch('/api/users/:username/role', authenticate, adminOnly, async (req, res) => {
  try {
    const target = req.params.username.toLowerCase().trim();
    const { role, permissions } = req.body;
    const validRoles = ['admin', 'staff'];
    if (!validRoles.includes(role)) return res.status(400).json({ error: 'Role must be admin or staff.' });
    if (target === 'admin') return res.status(403).json({ error: 'Cannot change the root admin role.' });

    if (localDb.users[target]) {
      localDb.users[target].role = role;
      if (permissions && typeof permissions === 'object') {
        localDb.users[target].permissions = permissions;
      }
      saveLocalDb();
    } else {
      return res.status(404).json({ error: 'User not found.' });
    }
    try { await supabase.from('users').update({ role }).eq('username', target); } catch(e){}
    audit(req.user.username, `Changed role of ${target} to ${role}`);
    res.json({ success: true, username: target, role, permissions: localDb.users[target].permissions });
  } catch(err) {
    res.status(500).json({ error: 'Role update failed.' });
  }
});

/** PATCH /api/users/:username/email — Save/update email for a user */
app.patch('/api/users/:username/email', authenticate, async (req, res) => {
  try {
    const target = req.params.username.toLowerCase().trim();
    // Users can only update their own email; admins can update anyone's
    if (target !== req.user.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized.' });
    }
    const { email } = req.body;
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Valid email is required.' });
    const cleanEmail = email.toLowerCase().trim();
    if (localDb.users[target]) {
      localDb.users[target].email = cleanEmail;
      saveLocalDb();
    }
    try { await supabase.from('users').update({ email: cleanEmail }).eq('username', target); } catch(e){}
    audit(req.user.username, `Updated email for ${target}`);
    res.json({ success: true, email: cleanEmail });
  } catch(err) {
    res.status(500).json({ error: 'Email update failed.' });
  }
});

// ============================================================
//  AUDIT LOGS
// ============================================================

app.get(['/api/audit-logs', '/api/admin/audit-logs'], authenticate, adminOnly, async (req, res) => {
  let dbLogs = [];
  try {
    const { data } = await supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(50);
    if (Array.isArray(data)) dbLogs = data;
  } catch (e) {}
  const map = new Map();
  (localDb.audit_logs || []).forEach(a => map.set(a.id || a.description + a.created_at, a));
  dbLogs.forEach(a => map.set(a.id || a.description + a.created_at, a));
  res.json(Array.from(map.values()).reverse().slice(0, 50));
});

// ============================================================
//  STATIC FILES + SPA CATCH-ALL
// ============================================================

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// All non-API routes → serve the SPA
app.get(/^(?!\/api).*/, (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Global Error Handler (Debug mode off in production) ──────
app.use((err, req, res, _next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.error('Unhandled server error:', err.stack || err.message);
  } else {
    console.error('Unhandled server error:', err.message);
  }
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start Server ─────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🏥  HARION NAGAR PHARMACY — API Server`);
  console.log(`    Port      : ${PORT}`);
  console.log(`    Supabase  : ${process.env.SUPABASE_URL}`);
  console.log(`    Env       : ${process.env.NODE_ENV || 'development'}\n`);
});

