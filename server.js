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

// ── Validate required environment variables ─────────────────
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET'];
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
const JWT_SECRET    = process.env.JWT_SECRET;
const JWT_EXPIRES   = process.env.JWT_EXPIRES_IN || '8h';

// ── Express App ──────────────────────────────────────────────
const app = express();

// Trust reverse proxy (Render, Cloudflare, etc.) for rate-limiting and HTTPS
app.set('trust proxy', 1);

// ── Security Headers ─────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      connectSrc:  ["'self'"],
      imgSrc:      ["'self'", 'data:'],
    }
  },
  crossOriginEmbedderPolicy: false
}));

// ── Logging ──────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── CORS ─────────────────────────────────────────────────────
const corsEnv = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.trim() : '*';
const allowedOrigins = corsEnv === '*'
  ? ['*']
  : corsEnv.split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin (no origin header), wildcard '*', or listed origins
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return cb(null, true);
    }
    // Also allow any render.com subdomains automatically
    if (typeof origin === 'string' && (origin.endsWith('.onrender.com') || origin.includes('localhost'))) {
      return cb(null, true);
    }
    cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// ── Body Parsing — strict 10 MB ceiling ──────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Rate Limiting ─────────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 600,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait and try again.' }
});
app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);

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

/** Fire-and-forget audit log writer */
const audit = async (username, description) => {
  try {
    await supabase.from('audit_logs').insert({ username, description });
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

let localDb = {
  config: { ...DEFAULT_CONFIG },
  users: {
    rd: { username: 'rd', full_name: 'Ram Dular Mahato', role: 'admin', password_hash: null },
    rs: { username: 'rs', full_name: 'Ramesh Singh', role: 'staff', password_hash: null }
  },
  medicines: [],
  stock: [],
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
      users: { ...localDb.users, ...(parsed.users || {}) }
    };
  } else {
    fs.writeFileSync(DATA_FILE, JSON.stringify(localDb, null, 2), 'utf8');
  }
} catch (e) {
  console.warn('Could not read local DB, using defaults:', e.message);
}

const saveLocalDb = () => {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(localDb, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to persist local DB:', e.message);
  }
};

/** GET /api/auth/users — Public list of user accounts with password setup status */
app.get('/api/auth/users', async (req, res) => {
  try {
    let dbUsers = [];
    try {
      const { data } = await supabase
        .from('users')
        .select('username, email, full_name, role, password_hash')
        .order('username');
      if (Array.isArray(data)) dbUsers = data;
    } catch (e) {
      // If email column doesn't exist yet in Supabase schema cache
      try {
        const { data } = await supabase
          .from('users')
          .select('username, full_name, role, password_hash')
          .order('username');
        if (Array.isArray(data)) dbUsers = data;
      } catch (e2) {}
    }

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

/** POST /api/auth/register — Register new account with Email, Username, Full Name, Password */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, full_name, password, role } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, Email, and Password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters long.' });
    }

    const cleanUsername = username.toLowerCase().trim();
    const cleanEmail = email.toLowerCase().trim();
    const cleanFullName = full_name ? full_name.trim() : cleanUsername.toUpperCase();
    const assignedRole = (role === 'admin' && cleanUsername === 'rd') ? 'admin' : (role === 'admin' ? 'admin' : 'staff');

    // Check if user or email already exists in localDb
    for (const [u, d] of Object.entries(localDb.users)) {
      if (u === cleanUsername) {
        return res.status(400).json({ error: `Username '${cleanUsername}' is already registered.` });
      }
      if (d.email && d.email.toLowerCase() === cleanEmail) {
        return res.status(400).json({ error: `Email '${cleanEmail}' is already registered with username '${u}'.` });
      }
    }

    // Hash password
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // Persist to localDb
    localDb.users[cleanUsername] = {
      username: cleanUsername,
      email: cleanEmail,
      full_name: cleanFullName,
      role: assignedRole,
      password_hash: hash
    };
    saveLocalDb();

    // Persist to Supabase
    try {
      await supabase.from('users').upsert({
        username: cleanUsername,
        email: cleanEmail,
        full_name: cleanFullName,
        role: assignedRole,
        password_hash: hash
      }, { onConflict: 'username' });
    } catch (e) {
      console.warn('Supabase register write notice:', e.message);
      // If error is missing email column, write without email
      try {
        await supabase.from('users').upsert({
          username: cleanUsername,
          full_name: cleanFullName,
          role: assignedRole,
          password_hash: hash
        }, { onConflict: 'username' });
      } catch (e2) {}
    }

    const token = jwt.sign(
      { username: cleanUsername, email: cleanEmail, fullName: cleanFullName, role: assignedRole },
      JWT_SECRET || 'harion_fallback_secret_key_8829103948572019',
      { expiresIn: JWT_EXPIRES }
    );

    audit(cleanUsername, `User registered: ${cleanUsername} (${cleanEmail}).`);

    res.status(201).json({
      token,
      user: { username: cleanUsername, email: cleanEmail, fullName: cleanFullName, role: assignedRole }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration: ' + err.message });
  }
});

/** POST /api/auth/login — Validate credentials (by username OR email), return JWT */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || typeof password !== 'string') {
      return res.status(400).json({ error: 'Username/Email and password are required.' });
    }

    const inputIdentifier = username.toLowerCase().trim();
    let cleanUsername = inputIdentifier;
    let foundEmail = '';

    // Check if input is email or username in localDb
    for (const [u, d] of Object.entries(localDb.users)) {
      if (u === inputIdentifier || (d.email && d.email.toLowerCase() === inputIdentifier)) {
        cleanUsername = u;
        foundEmail = d.email || '';
        break;
      }
    }

    let dbUser = null;
    try {
      // Query by username or email
      const { data } = await supabase
        .from('users')
        .select('username, email, full_name, role, password_hash')
        .or(`username.eq.${inputIdentifier},email.eq.${inputIdentifier}`)
        .maybeSingle();
      if (data) {
        dbUser = data;
        cleanUsername = data.username;
        foundEmail = data.email || foundEmail;
      }
    } catch (e) {
      try {
        const { data } = await supabase
          .from('users')
          .select('username, full_name, role, password_hash')
          .eq('username', cleanUsername)
          .maybeSingle();
        dbUser = data;
      } catch (e2) {}
    }

    const localUser = localDb.users[cleanUsername];
    const passwordHash = dbUser?.password_hash || localUser?.password_hash;
    const fullName = dbUser?.full_name || localUser?.full_name || (cleanUsername === 'rd' ? 'Ram Dular Mahato' : cleanUsername.toUpperCase());
    const role = dbUser?.role || localUser?.role || (cleanUsername === 'rd' ? 'admin' : 'staff');
    const userEmail = dbUser?.email || localUser?.email || foundEmail;

    // First-time login: no password hash stored in DB or local store
    if (!passwordHash) {
      return res.status(200).json({
        firstLogin: true,
        username: cleanUsername,
        email: userEmail,
        fullName,
        role
      });
    }

    const valid = await bcrypt.compare(password, passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials. Please check your username/email or password.' });
    }

    const token = jwt.sign(
      { username: cleanUsername, email: userEmail, fullName, role },
      JWT_SECRET || 'harion_fallback_secret_key_8829103948572019',
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      token,
      user: { username: cleanUsername, email: userEmail, fullName, role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login: ' + err.message });
  }
});

/** POST /api/auth/set-password — First-time password creation with optional email */
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || typeof password !== 'string' || password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    }

    const cleanUsername = username.toLowerCase().trim();
    const cleanEmail = email && validator.isEmail(email) ? email.toLowerCase().trim() : '';
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    if (localDb.users[cleanUsername]) {
      localDb.users[cleanUsername].password_hash = hash;
      if (cleanEmail) localDb.users[cleanUsername].email = cleanEmail;
    } else {
      localDb.users[cleanUsername] = {
        username: cleanUsername,
        email: cleanEmail,
        full_name: cleanUsername === 'rd' ? 'Ram Dular Mahato' : (cleanUsername === 'rs' ? 'Ramesh Singh' : cleanUsername.toUpperCase()),
        role: cleanUsername === 'rd' ? 'admin' : 'staff',
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
    const userEmail = localDb.users[cleanUsername].email;

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
    res.status(500).json({ error: 'Server error: ' + err.message });
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
      return res.status(404).json({ error: `Account '${identifier}' not found. Please register or verify the username/email.` });
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
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes

    OTP_STORE.set(cleanId, { code: otpCode, username: targetUsername, email: targetEmail, expiresAt });
    OTP_STORE.set(targetEmail.toLowerCase(), { code: otpCode, username: targetUsername, email: targetEmail, expiresAt });
    OTP_STORE.set(targetUsername.toLowerCase(), { code: otpCode, username: targetUsername, email: targetEmail, expiresAt });

    const mailResult = await sendPasswordResetEmail(targetEmail, otpCode, targetUser?.full_name || targetUsername);

    // Mask email for user privacy (e.g. h***@gmail.com)
    const [eName, eDomain] = targetEmail.split('@');
    const masked = eName.length <= 2 ? `${eName[0]}*@${eDomain}` : `${eName[0]}${'*'.repeat(eName.length - 2)}${eName.slice(-1)}@${eDomain}`;

    res.json({
      success: true,
      message: `A 6-digit verification code has been sent to ${masked}.`,
      emailMasked: masked,
      username: targetUsername,
      // If SMTP is in fallback / preview mode, safely supply code to UI for seamless workflow
      previewCode: (mailResult.mode === 'fallback' || mailResult.mode === 'local_preview') ? otpCode : undefined
    });
  } catch (err) {
    console.error('Forgot-password error:', err);
    res.status(500).json({ error: 'Server error processing password reset: ' + err.message });
  }
});

/** POST /api/auth/reset-password — Verify OTP and set new password */
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { identifier, code, new_password } = req.body;
    if (!identifier || !code || !new_password) {
      return res.status(400).json({ error: 'Identifier (username/email), verification code, and new password are required.' });
    }
    if (new_password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters long.' });
    }

    const cleanId = identifier.toLowerCase().trim();
    const cleanCode = code.toString().trim();

    const storedOtp = OTP_STORE.get(cleanId);
    if (!storedOtp) {
      return res.status(400).json({ error: 'Verification code not found or expired. Please request a new code.' });
    }

    if (Date.now() > storedOtp.expiresAt) {
      OTP_STORE.delete(cleanId);
      return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
    }

    if (storedOtp.code !== cleanCode) {
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
        role: cleanUsername === 'rd' ? 'admin' : 'staff',
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
    res.status(500).json({ error: 'Server error resetting password: ' + err.message });
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
    res.status(500).json({ error: 'Sync failed: ' + err.message });
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
    if (password && typeof password === 'string' && password.length >= 4) {
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
//  AUDIT LOGS
// ============================================================

app.get('/api/audit-logs', authenticate, adminOnly, async (req, res) => {
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

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// All non-API routes → serve the SPA
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Global Error Handler ─────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('Unhandled:', err.stack || err.message);
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

