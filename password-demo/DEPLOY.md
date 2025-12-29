# Deployment Guide

This guide covers deploying the HIBP Password Checker to production.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│   Vercel    │────▶│   Railway   │────▶│  HIBP Data      │
│  (Next.js)  │     │(Rust Server)│     │  (Volume)       │
└─────────────┘     └─────────────┘     └─────────────────┘
```

## Prerequisites

- GitHub repository connected to both Vercel and Railway
- Railway account with billing enabled (for volumes)
- Vercel account

---

## Deploy UI to Vercel

### Option 1: Vercel Dashboard (Recommended)

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repository: `p0mvn/simplepir`
3. Configure the project:
   - **Framework Preset**: Next.js
   - **Root Directory**: `password-demo/ui`
   - **Build Command**: `npm run build`
   - **Output Directory**: `.next`

4. Add environment variable:
   ```
   NEXT_PUBLIC_API_URL = https://your-railway-app.railway.app
   ```
   (You'll get this URL after deploying to Railway)

5. Click **Deploy**

### Option 2: Vercel CLI

```bash
cd password-demo/ui
npm i -g vercel
vercel login
vercel --prod
```

---

## Deploy Server to Railway

### Step 1: Create Railway Project

1. Go to [railway.app/new](https://railway.app/new)
2. Click **Deploy from GitHub repo**
3. Select `p0mvn/simplepir`

### Step 2: Configure Build Settings

In the Railway service settings:

- **Root Directory**: Leave empty (builds from repo root)
- **Builder**: Dockerfile
- **Dockerfile Path**: `password-demo/server/Dockerfile`
- **Watch Paths**: `password-demo/server/**`, `password-demo/hibp/**`

### Step 3: Add Volume for HIBP Data

1. In your Railway service, click **+ New** → **Volume**
2. Configure:
   - **Mount Path**: `/app/data/ranges`
   - **Size**: 50GB (full dataset is ~38GB)

### Step 4: Set Environment Variables

```
PORT=3000
HIBP_DATA_DIR=/app/data/ranges
HIBP_MEMORY_MODE=true
RUST_LOG=info
```

### Step 5: Initial Data Load

Since the volume starts empty, you need to populate it. Options:

**Option A: Railway Shell (Recommended for small datasets)**
```bash
# In Railway shell
cd /app/data/ranges
curl -s --retry 10 --remote-name-all --parallel --parallel-max 50 \
  "https://api.pwnedpasswords.com/range/{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}"
```

**Option B: Pre-built Data Image**
Create a Docker image with data baked in (larger image, but faster cold starts).

**Option C: GitHub Actions + Railway API**
Use the `sync-hibp.yml` workflow to download data and trigger redeployment.

### Step 6: Generate Domain

In Railway settings, go to **Settings** → **Networking** → **Generate Domain**

Copy the URL (e.g., `hibp-server-production.up.railway.app`)

### Step 7: Update Vercel

Go back to Vercel and update the environment variable:
```
NEXT_PUBLIC_API_URL = https://hibp-server-production.up.railway.app
```

Redeploy if needed.

---

## GitHub Actions Setup (Optional)

For daily HIBP data sync:

1. Go to Railway Dashboard → **Account Settings** → **Tokens**
2. Create a new token
3. In GitHub repo settings, add secrets:
   - `RAILWAY_TOKEN`: Your Railway API token
   - `RAILWAY_PROJECT_ID`: Found in Railway project settings URL
   - `RAILWAY_SERVICE_ID`: Found in Railway service settings

The workflow at `.github/workflows/sync-hibp.yml` will:
- Run daily at 2 AM UTC
- Download fresh HIBP data
- Trigger Railway redeploy

---

## Verify Deployment

### Check Server Health
```bash
curl https://your-railway-app.railway.app/health
# Expected: {"status":"ok","ranges_loaded":1048576,"total_hashes":...}
```

### Check Password
```bash
curl -X POST https://your-railway-app.railway.app/check \
  -H "Content-Type: application/json" \
  -d '{"hash":"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
# Expected: {"pwned":true,"count":...}
```

### Test UI
Visit your Vercel deployment URL and try checking a password.

---

## Cost Estimates

| Service | Free Tier | Production |
|---------|-----------|------------|
| Vercel | ✅ Hobby tier works | $20/mo Pro |
| Railway | ❌ Need volume ($5+) | ~$20-50/mo |

**Railway breakdown:**
- Compute: ~$5-10/mo (depending on memory)
- Volume: $0.15/GB/mo × 50GB = ~$7.50/mo
- Egress: $0.10/GB after 100GB free

---

## Troubleshooting

### Server shows 0 hashes
- Check volume is mounted correctly
- Verify data was downloaded to `/app/data/ranges`
- Check `HIBP_DATA_DIR` environment variable

### UI shows "Server Offline"
- Verify `NEXT_PUBLIC_API_URL` is set correctly
- Check Railway service is running
- Verify CORS is enabled (it is by default)

### Slow cold starts
- Railway: Increase memory allocation
- Consider keeping service awake with health checks

---

## Local Testing

```bash
# Terminal 1: Start server
cd password-demo/server
HIBP_DATA_DIR=../data/ranges cargo run --release

# Terminal 2: Start UI
cd password-demo/ui
NEXT_PUBLIC_API_URL=http://localhost:3000 npm run dev
```

