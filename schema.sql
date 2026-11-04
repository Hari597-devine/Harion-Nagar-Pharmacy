-- ============================================================
--  HARION NAGAR PHARMACY — Supabase PostgreSQL Schema
--  Run this entire script once in: Supabase Dashboard → SQL Editor
--  It is safe to re-run; all statements use IF NOT EXISTS / ON CONFLICT DO NOTHING
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
--  TABLE: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  username    TEXT        UNIQUE NOT NULL,
  email       TEXT        UNIQUE,
  full_name   TEXT        NOT NULL,
  role        TEXT        NOT NULL DEFAULT 'staff' CHECK (role IN ('admin', 'staff')),
  password_hash TEXT      DEFAULT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure email column exists if users table was created previously without it
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_email_key'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
  END IF;
EXCEPTION
  WHEN OTHERS THEN NULL;
END $$;

-- ============================================================
--  TABLE: medicines  (Unique index of drug names)
-- ============================================================
CREATE TABLE IF NOT EXISTS medicines (
  id       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  name     TEXT         UNIQUE NOT NULL,
  unit     TEXT         NOT NULL DEFAULT 'PCS',
  hs_code  TEXT         DEFAULT '',
  mrp      NUMERIC(10,2) DEFAULT 0,
  vat      NUMERIC(5,2)  DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: stock  (Composite key: medicine + batch + expiry)
-- ============================================================
CREATE TABLE IF NOT EXISTS stock (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  medicine_id    UUID         REFERENCES medicines(id) ON DELETE SET NULL,
  medicine_name  TEXT         NOT NULL,
  hs_code        TEXT         DEFAULT '',
  unit           TEXT         DEFAULT 'PCS',
  batch          TEXT         DEFAULT '',
  expiry         TEXT         DEFAULT '',   -- stored as YYYY-MM
  quantity       INTEGER      NOT NULL DEFAULT 0,
  cost_price     NUMERIC(10,2) DEFAULT 0,
  mrp            NUMERIC(10,2) DEFAULT 0,
  vat            NUMERIC(5,2)  DEFAULT 0,
  created_at     TIMESTAMPTZ  DEFAULT NOW()
);

-- ============================================================
--  TABLE: purchases  (Immutable supplier stock-entry ledger)
-- ============================================================
CREATE TABLE IF NOT EXISTS purchases (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  username         TEXT        NOT NULL,
  supplier         TEXT        DEFAULT '',
  bill_no          TEXT        DEFAULT '',
  items            JSONB       NOT NULL DEFAULT '[]',
  transaction_time BIGINT,                     -- JS Date.now() epoch ms
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: sales  (Immutable customer invoice ledger)
-- ============================================================
CREATE TABLE IF NOT EXISTS sales (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  bill_no          TEXT        UNIQUE NOT NULL,
  username         TEXT        NOT NULL,
  customer_name    TEXT        DEFAULT '',
  payment_mode     TEXT        DEFAULT 'Cash',
  billing_mode     TEXT        DEFAULT 'General',
  subtotal         NUMERIC(12,2) DEFAULT 0,
  discount         NUMERIC(10,2) DEFAULT 0,
  tax              NUMERIC(10,2) DEFAULT 0,
  grand_total      NUMERIC(12,2) DEFAULT 0,
  cost_of_goods    NUMERIC(12,2) DEFAULT 0,
  net_before_vat   NUMERIC(12,2) DEFAULT 0,
  items            JSONB       NOT NULL DEFAULT '[]',
  note             TEXT        DEFAULT '',
  transaction_time BIGINT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: returns  (Immutable returns/refund ledger)
-- ============================================================
CREATE TABLE IF NOT EXISTS returns (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  return_no        TEXT        UNIQUE NOT NULL,
  username         TEXT        NOT NULL,
  customer_name    TEXT        DEFAULT '',
  payment_mode     TEXT        DEFAULT 'Cash',
  sale_ref         TEXT        DEFAULT '',
  items            JSONB       NOT NULL DEFAULT '[]',
  grand_total      NUMERIC(12,2) DEFAULT 0,
  cost_of_goods    NUMERIC(12,2) DEFAULT 0,
  net_before_vat   NUMERIC(12,2) DEFAULT 0,
  note             TEXT        DEFAULT '',
  transaction_time BIGINT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: adjustments  (Stock modification audit trail)
-- ============================================================
CREATE TABLE IF NOT EXISTS adjustments (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  username         TEXT        NOT NULL,
  stock_id         UUID        REFERENCES stock(id) ON DELETE SET NULL,
  medicine_name    TEXT        NOT NULL,
  batch            TEXT        DEFAULT '',
  old_quantity     INTEGER     DEFAULT 0,
  new_quantity     INTEGER     DEFAULT 0,
  quantity_change  INTEGER     DEFAULT 0,
  old_cost         NUMERIC(10,2) DEFAULT 0,
  reason           TEXT        DEFAULT '',
  transaction_time BIGINT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: audit_logs  (System event log)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  username    TEXT        NOT NULL,
  description TEXT        NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
--  TABLE: config  (Single-row global system configuration)
-- ============================================================
CREATE TABLE IF NOT EXISTS config (
  id               INTEGER     PRIMARY KEY DEFAULT 1,
  name             TEXT        DEFAULT 'HARION NAGAR HOSPITAL',
  addr             TEXT        DEFAULT 'Harion-4, Sasapur, Sarlahi',
  pan              TEXT        DEFAULT '609836604',
  prefix           TEXT        DEFAULT 'BASR',
  vat              NUMERIC(5,2) DEFAULT 0,
  footer1          TEXT        DEFAULT 'Don''t accept substitute, ask your DOCTOR first. E. & O. E.',
  footer2          TEXT        DEFAULT 'Medicines sold would not be taken back after seven days.',
  expiry_days      INTEGER     DEFAULT 90,
  low_stock_level  INTEGER     DEFAULT 10,
  returns_enabled  BOOLEAN     DEFAULT TRUE,
  discount_enabled BOOLEAN     DEFAULT TRUE,
  adj_password     BOOLEAN     DEFAULT TRUE,
  auto_print       BOOLEAN     DEFAULT TRUE,
  accent           TEXT        DEFAULT '',
  seq              INTEGER     DEFAULT 1,
  rs_counter       INTEGER     DEFAULT 1,
  CHECK (id = 1)
);

-- ============================================================
--  SEED DATA
-- ============================================================

-- Insert the single config row (safe to re-run)
INSERT INTO config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Insert the two default pharmacy users (passwords null = first-login prompt)
INSERT INTO users (username, full_name, role)
VALUES
  ('rd', 'Ram Dular Mahato', 'admin'),
  ('rs', 'Ramesh Singh',     'staff')
ON CONFLICT (username) DO NOTHING;

-- ============================================================
--  PERFORMANCE INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_stock_medicine_id      ON stock(medicine_id);
CREATE INDEX IF NOT EXISTS idx_stock_medicine_name    ON stock(medicine_name);
CREATE INDEX IF NOT EXISTS idx_stock_quantity         ON stock(quantity);
CREATE INDEX IF NOT EXISTS idx_sales_username         ON sales(username);
CREATE INDEX IF NOT EXISTS idx_sales_created_at       ON sales(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_payment_mode     ON sales(payment_mode);
CREATE INDEX IF NOT EXISTS idx_purchases_created_at   ON purchases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_returns_created_at     ON returns(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_adjustments_created_at ON adjustments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at  ON audit_logs(created_at DESC);

-- ============================================================
--  ROW LEVEL SECURITY (Recommended for production)
--  Since Express uses service_role key (bypasses RLS), these
--  policies protect against direct anon-key access.
-- ============================================================
ALTER TABLE users        ENABLE ROW LEVEL SECURITY;
ALTER TABLE medicines    ENABLE ROW LEVEL SECURITY;
ALTER TABLE stock        ENABLE ROW LEVEL SECURITY;
ALTER TABLE purchases    ENABLE ROW LEVEL SECURITY;
ALTER TABLE sales        ENABLE ROW LEVEL SECURITY;
ALTER TABLE returns      ENABLE ROW LEVEL SECURITY;
ALTER TABLE adjustments  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE config       ENABLE ROW LEVEL SECURITY;

-- Block all direct anonymous/authenticated access (all access via Express service key only)
CREATE POLICY "deny_all_users"       ON users       FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_medicines"   ON medicines   FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_stock"       ON stock       FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_purchases"   ON purchases   FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_sales"       ON sales       FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_returns"     ON returns     FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_adjustments" ON adjustments FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_audit_logs"  ON audit_logs  FOR ALL TO anon, authenticated USING (false);
CREATE POLICY "deny_all_config"      ON config      FOR ALL TO anon, authenticated USING (false);

