# 🏥 HARION NAGAR PHARMACY INVENTORY — Management System

Enterprise-grade Pharmacy Billing, Inventory Tracking, Graphical Analytics, and Accounts Ledger application designed specifically for **HARION NAGAR PHARMACY** (Harion-4, Sasapur, Sarlahi).

---

## ⚡ Architecture & Decoupled Stack

- **Backend (`server.js`)**: Isolated Node.js + Express REST API engine with JWT token authentication, bcrypt password hashing, rigid CORS, rate limiting, and dual-layer data persistence (Supabase PostgreSQL + local fallback mirror).
- **Database (Supabase PostgreSQL)**: Strongly-typed relational schema (`schema.sql`) with tables (`users`, `medicines`, `stock`, `purchases`, `sales`, `returns`, `adjustments`, `audit_logs`, `config`).
- **Frontend Client (`public/index.html`)**: Decoupled Single Page Application (SPA) built with Inter & JetBrains Mono typography, inline SVG icons, client-side offline cache fallback, Bikram Sambat (BS) date conversion, A4/A5 billing print module, and interactive graphical inventory/sales charts.
- **Hosting**: 100% Free on **Supabase** (Database) and **Render.com** (Node.js API + Static Frontend).

---

## 🚀 Quick Setup Guide

### 1. Database Setup (Supabase)
1. Create a free account at [Supabase.com](https://supabase.com).
2. Create a new project (e.g. `harion-nagar-pharmacy`).
3. Open **SQL Editor** in your Supabase dashboard.
4. Copy the entire contents of [`schema.sql`](./schema.sql) and click **Run**.
5. Navigate to **Project Settings** → **API**:
   - Copy **Project URL**
   - Copy **`service_role` secret key** (bypasses RLS on backend)

### 2. Environment Configuration (`.env`)
Create or edit your [`.env`](./.env) file:
```env
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_SERVICE_KEY=your-supabase-service-role-key-here
JWT_SECRET=super_secure_random_64_character_string_here
JWT_EXPIRES_IN=8h
PORT=3000
CORS_ORIGIN=http://localhost:3000
BCRYPT_ROUNDS=12
NODE_ENV=development
```

### 3. Install & Run Locally
```bash
# Install dependencies
npm install

# Start production server
npm start

# Or start in development mode with auto-reload
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 📋 Default Credentials
- **Admin**: `rd` (Ram Dular Mahato) — Prompts to create secure password on first login.
- **Staff**: `rs` (Ramesh Singh) — Prompts to create secure password on first login.

---

## 🌐 Deploy Free to Render.com
1. Push repository to GitHub or GitLab.
2. In [Render Dashboard](https://dashboard.render.com), create a new **Web Service**.
3. Select your repository.
4. Set:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Plan**: `Free`
5. Add the environment variables from `.env` (`SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `JWT_SECRET`, etc.).
6. Click **Deploy**. Your app will be live at `https://your-app.onrender.com`.

---

## 📡 API Endpoints Overview

| Method | Endpoint | Description | Clearance |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Validates credentials & returns JWT | Public |
| `POST` | `/api/auth/set-password` | Sets password for first-time login | Public |
| `GET` | `/api/pharmacy/state` | Full system initial load map | Authenticated |
| `POST` | `/api/pharmacy/sync` | Batch synchronization endpoint | Authenticated |
| `GET` | `/api/pharmacy/inventory-dashboard` | Aggregate inventory statistics | Authenticated |
| `GET` | `/api/pharmacy/accounts-dashboard` | Real-time financial trading ledger | Admin Only |
| `GET/POST`| `/api/medicines` | Catalog medicine items | Authenticated |
| `GET` | `/api/stock` | Current inventory units by batch | Authenticated |
| `GET/POST`| `/api/purchases` | Supplier stock entry purchases | Authenticated |
| `GET/POST`| `/api/sales` | Customer sales invoices | Authenticated |
| `GET/POST`| `/api/returns` | Sales return and refunds | Authenticated |
| `GET/POST`| `/api/adjustments` | Stock damage/loss adjustments | Authenticated |
| `DELETE` | `/api/transactions/:type/:id`| Atomic transaction reversal | Admin Only |
| `GET/PUT` | `/api/config` | System branding & sequence config | Admin Only |
| `POST` | `/api/users/reset-password` | Admin password reset | Admin Only |

---

## 📜 Business Logic & Regional Compliance
- **Pharmacy Location**: HARION NAGAR PHARMACY, Harion-4, Sasapur, Sarlahi (PAN: `609836604`).
- **Calendar Engine**: Verified Bikram Sambat (BS) matrix for years 2082–2091 with `bs(t)` converter.
- **Print Layout**: Precision A5 Landscape layout formatted for dot-matrix and thermal receipt printing.
- **Currency In-Words**: Nepali/South Asian numbering denominations (**LAKH**, **CRORE**, and **PAISA**).
