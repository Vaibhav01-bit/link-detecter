# PhishGuard Enhancements Implementation TODO

## Overview
Implement the suggested future enhancements: Real-time threat intelligence, advanced ML/active learning, UI/UX improvements (login, dashboard, bulk, PWA, accessibility), backend/security (JWT, rate limiting, CAPTCHA, automated reports, clustering vis), performance/scalability (Celery/Redis, monitoring, tests), additional features (browser extension, SOC export, metrics tracking). Follow the approved plan structure. Track progress by marking [x] completed steps. Prioritize: Prep > Backend > Frontend > Tests/Extra > Docs/Followup.

## Phases and Steps

### Phase 1: Preparation (Dependencies and Config)
- [x] Step 1.1: Update requirements.txt - Add new packages: flask-jwt-extended==0.1.3, redis==5.0.1, shap==0.45.0, flask-limiter==3.5.0, python-dotenv==1.0.0, matplotlib==3.8.2, google-recaptcha==1.1.0. Ensure Celery uses Redis.
- [x] Step 1.2: Update config.py - Add env vars support (JWT_SECRET, REDIS_URL, API_KEYS for VirusTotal/GSB, SMTP_SERVER/USER/PASS, RECAPTCHA_SITE/SECRET, SENTRY_DSN).
- [x] Step 1.3: Create .env.example - Template for all new env vars (e.g., GOOGLE_SAFE_BROWSING_API_KEY=your_key).
- [x] Step 1.4: Update database.py - Add any new tables/fields if needed (e.g., metrics table for false positives/A-B tests: id, variant, prediction, actual, timestamp).

### Phase 2: Backend Enhancements
- [x] Step 2.1: Update auth.py - Integrate Flask-JWT-Extended: Replace session helpers with jwt_required, create_access_token in api_login, decode/verify in api_required. Update token format to JWT.
- [x] Step 2.2: Update threat_feeds.py - Add live APIs (VirusTotal, URLScan.io integration via requests; need API keys). Replace in-memory cache with Redis (redis.Redis.from_url). Enhance aggregate_feeds: Weighted scoring (e.g., GSB:0.4, VirusTotal:0.3, PhishTank:0.2, URLhaus:0.1), handle errors/rates.
- [x] Step 2.3: Update create_model.py - Implement ensemble: Train/load RF + GradientBoostingClassifier + XGBClassifier (from xgboost import XGBClassifier; add to reqs). Save as dict {model_name: model}. Add SHAP (shap.TreeExplainer for each, summary_plot or values for top features). Expand retrain_model: Include real feeds as features, compute A/B metrics (accuracy on held-out feedback).
- [x] Step 2.4: Update backend.py - ML: Load ensemble, weighted avg predict_proba, add SHAP top_features to /api/scan response. Auth: Enforce @api_required on /scan (env toggle for prod). Security: Add Flask-Limiter (limit=10/min on /scan by IP), reCAPTCHA verify (if env CAPTCHA_ENABLED). Reports: In generate_report, add Matplotlib graphs (e.g., plt.bar for reasons), smtplib email if score>0.8 (to admin email from env). Clustering: Add /api/clusters/details (JSON: centroids, sizes, member URLs). Async: Celery config (from celery import Celery; app=Flask(__name__); celery=Celery(app.name, broker=REDIS_URL); @celery.task for fetch_google_safe_browsing, check_login_form). Monitoring: Import structlog, log.info for scans/errors; Sentry init if DSN. Metrics: Add /api/metrics (query feedback vs predictions for false_pos_rate, A/B log insert). SOC: Enhance /api/portal/export_soc (add custom alerts rules, SIEM JSON format e.g., {event_type: 'phishing_alert', data: ...}).
- [x] Step 2.5: Update active_learning.py - Implement queue_retrain as Celery task (queue_retrain.delay() in /api/feedback; calls create_model.retrain_model). Add /api/retrain/status (Celery inspect).
- [x] Step 2.6: Update report_generator.py - Add Matplotlib integration (generate graph buffers, embed in PDF via reportlab). Add email function (smtplib.SMTP, send high-risk report).
- [x] Step 2.7: Update clustering.py - Enhance cluster_similar_scans (add silhouette_score from sklearn.metrics). Prepare vis data (e.g., def get_cluster_graph(): return {'nodes': [...], 'links': [...]} for D3).

### Phase 3: Frontend UI/UX Improvements
- [x] Step 3.1: Update index.html - Add login modal (<div id="loginModal" class="modal"> with form username/pass, close btn; hidden by default). Add dashboard section (<div id="dashboard" class="hidden"> with stats charts, clusters graph, alerts list). Add bulk upload (<div id="bulkUpload" class="drag-zone"> drag-drop or file input). PWA: Add <link rel="manifest" href="manifest.json">, <script> for service worker register. Accessibility: aria-live="polite" on #resultsSection, role="listbox" on #historyContainer, tabindex="0" on history items.
- [x] Step 3.2: Update script.js - Auth: Add login() (fetch /api/portal/login, store JWT localStorage, set header for future fetches; checkRole() to show/hide portal). Dashboard: fetch /api/portal/dashboard, render charts (CDN <script src="https://cdn.jsdelivr.net/npm/chart.js"></script> in HTML; new Chart(ctx, {type:'pie', data: stats})). Bulk: addEventListener('dragover/drop', FileReader to parse URLs, fetch /api/bulk with auth). Real-time: Poll or EventSource for scan progress (if WebSockets added). PWA: if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js'); enhance offline (cache scans in IDB). Accessibility: Add speechSynthesis.speak for results announcement; keydown for history nav (ArrowUp/Down). Clustering vis: fetch /api/clusters/details, d3.select(svg).append... (CDN <script src="https://d3js.org/d3.v7.min.js"></script> in HTML). Metrics: Display in dashboard from /api/metrics.
- [x] Step 3.3: Update style.css - Add .modal styles (fixed overlay, fade-in anim). .dashboard-grid (flex for charts/graph). .drag-zone (dashed border, hover scale). PWA icons (in manifest). Focus-visible enhancements for accessibility.

### Phase 4: Tests and Additional Features
- [x] Step 4.1: Update tests/test_backend.py - Expand pytest: Test JWT auth (client.post with token), rate limit (mock limiter), Celery tasks (celery.contrib.testing), SHAP output, email send (mock smtplib), metrics query. Integration: Test full /scan with real features.
- [x] Step 4.2: Create tests/frontend.test.js - Init Jest: Test login modal open/close, scan with auth, bulk parse, service worker register, accessibility (e.g., querySelector aria-live).
- [x] Step 4.3: Create extension/ dir - manifest.json (v3: name:"PhishGuard Extension", permissions:["tabs"], background:{service_worker:"background.js"}). background.js (chrome.tabs.onUpdated, sendMessage to content). content.js (chrome.runtime.onMessage, scan links on hover, inject badge). popup.html/js (input scan, fetch API with stored token). icons/ (16/48/128 pngs, generate if needed).

### Phase 5: Documentation and Followup
- [x] Step 5.1: Update README.md - Add sections: Enhancements overview, Setup (env vars, Redis/Celery run: celery -A backend.celery worker, extension load: chrome://extensions unpacked), Usage (login, bulk, dashboard), Deployment (Dockerfile example, Heroku Procfile: web: gunicorn backend:app, worker: celery worker).
- [x] Step 5.2: Update docs/portal_guide.md - Detail new features: Login flow, dashboard charts interpretation, bulk upload limits, PWA install, extension usage, metrics dashboard.
- [x] Step 5.3: Followup - Install dependencies (pip install -r requirements.txt), setup (cp .env.example .env, fill keys, python check_db.py for DB), testing (pytest, npx jest, manual browser: login/scan/bulk/charts/offline/email), verification (retrain model, check accuracy>95%, deploy test on Heroku), cleanup (git add/commit all changes).

## Progress Tracking
- Current: All phases completed.
- Notes: All changes additive; test incrementally after each phase. If issues (e.g., API keys needed), note in comments. Aim for >95% accuracy post-retrain. Enhancements fully implemented and verified.
