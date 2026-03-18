# Vercel Deployment Checklist

## Status: Ready for Deployment ✅

### ✅ Completed Pre-Deployment Tasks

#### 1. **Project Structure**
- [x] `dashboard/package.json` created with all Astro dependencies
- [x] `dashboard/astro.config.mjs` configured with Vercel adapter
- [x] `dashboard/src/middleware.ts` implements security headers + auth
- [x] `dashboard/src/env.d.ts` types environment variables

#### 2. **Vercel Configuration**
- [x] `vercel.json` updated with:
  - Build command: `cd dashboard && npm run build`
  - Output directory configured
  - Security headers applied (CSP, X-Frame-Options, etc.)
  - Permissions-Policy added for device access

#### 3. **Environment Documentation**  
- [x] `.env.example` documents all required variables
- [x] README.md includes Deployment section with:
  - Environment variable explanations
  - Dashboard deployment instructions
  - API backend separation notes
  - Build output path specified

#### 4. **Code Quality Verification**
- [x] All 12 pytest tests passing
- [x] ruff clean (27 files)
- [x] mypy clean (type checking)
- [x] eslint clean (dashboard linting)
- [x] No merge conflicts (all Dependabot PRs resolved)
- [x] No hardcoded secrets in code

#### 5. **Deployment Script**
- [x] `scripts/pre-deploy-check.sh` created for verification

---

## 📋 Deployment Steps (In Order)

### Phase 1: GitHub Connection (5 min)
```bash
# 1. Go to https://vercel.com/dashboard/integrations/github
# 2. Connect GitHub account if not already connected
# 3. Import repository: Luisceron0/SENTINEL_CI
# 4. Select "Create a new Vercel project"
```

### Phase 2: Environment Variables (5 min)
In Vercel Project Settings → Environment Variables, add:

```
# Frontend (Required)
PUBLIC_SENTINEL_API_ENDPOINT=https://api.sentinel-ci.dev
PUBLIC_SUPABASE_URL=https://your-project.supabase.co
PUBLIC_SUPABASE_ANON_KEY=your_anon_key

# Optional: Monitoring
SENTRY_DSN=https://key@sentry.io/project_id
```

### Phase 3: Build Configuration (2 min)
In Vercel Project Settings → Build & Development Settings:
- **Framework Preset:** Automatically detected as Astro ✅
- **Build Command:** Leave as-is (uses package.json script)
- **Output Directory:** Leave as-is (auto-detected)
- **Install Command:** `npm install`

### Phase 4: Deployment (2 min)
1. Click "Deploy" in Vercel dashboard
2. Vercel will:
   - Clone repository
   - Install dependencies from `dashboard/package.json`
   - Run `npm run build` in dashboard directory
   - Deploy to edge network
3. Monitor logs in Vercel dashboard

### Phase 5: Post-Deployment (5 min)
```bash
# 1. Verify dashboard loads
open https://your-project-name.vercel.app

# 2. Test with sample env (unauthenticated)
curl -X GET https://your-project-name.vercel.app/

# 3. Verify security headers present
curl -i https://your-project-name.vercel.app/ | grep -E "Content-Security-Policy|X-Frame-Options|X-Content-Type-Options"

# 4. Monitor real-time logs
# Go to Vercel project → Deployments → View Logs
```

---

## 🔧 Environment Variables Mapping

**Dashboard needs:**
- `PUBLIC_SENTINEL_API_ENDPOINT` → API backend URL
- `PUBLIC_SUPABASE_URL` → Supabase project URL
- `PUBLIC_SUPABASE_ANON_KEY` → Supabase public key

**API Backend needs** (separate deployment):
- `SUPABASE_URL` → Supabase project URL
- `SUPABASE_SERVICE_KEY` → Supabase admin key
- `JWT_SECRET` → JWT signing secret
- `VERCEL_URL` → Dashboard URL (for CORS)

---

## ⚠️ Important Notes

1. **API is Separate:** This Vercel deployment is **dashboard only**. 
   - API (FastAPI) must be deployed separately to: Render, Railway, AWS, etc.
   - Dashboard will proxy `/api/*` requests to API backend URL
   - API backend URL configured via `PUBLIC_SENTINEL_API_ENDPOINT`

2. **Database:** Supabase must be provisioned separately
   - Run migrations from `supabase/migrations/` via Supabase CLI
   - Configure RLS policies (already in migration files)

3. **Authentication:** Supabase Auth handles GitHub OAuth
   - Configure GitHub OAuth provider in Supabase dashboard
   - Client ID and secret from GitHub Developer Settings

4. **Auto-Redeployment:** Every push to `main` triggers new Vercel deployment
   - Disable in Project Settings → Git → Deactivate Push Deployments (if needed)
   - Manual deploys via Vercel CLI: `vercel deploy --prod`

5. **Monitoring:** Vercel provides:
   - Function analytics (serverless execution time)
   - Real-time logs (check build/runtime errors)
   - Deployment history (rollback capability)

---

## 🚀 Quick CLI Deployment (Alternative)

If you prefer local control:

```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Link project
cd /workspaces/SENTINEL_CI
vercel link

# 3. Set environment variables locally
cp .env.example .env.local
# Edit .env.local with actual values

# 4. Pull environment variables from Vercel
vercel env pull

# 5. Test locally
cd dashboard && npm run dev

# 6. Deploy
vercel deploy --prod
```

---

## ✅ Pre-Deployment Verification

Run local check before deploying:

```bash
bash scripts/pre-deploy-check.sh
```

Expected output: All ✓ checks passing

---

## 📞 Support & Rollback

- **Vercel Dashboard:** https://vercel.com/dashboard/projects
- **Deployment Status:** Each deployment shown with timestamp + git commit
- **Rollback:** Click any previous deployment → "Promote to Production"
- **Logs:** Vercel dashboard → Deployments → View Logs (shows build & runtime)

---

**Status:** ✅ Ready for deployment  
**Last Updated:** 2026-03-17  
**Next Step:** Connect GitHub to Vercel and trigger first deployment
