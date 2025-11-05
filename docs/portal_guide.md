# PhishGuard Enterprise Portal Guide

## Overview
The PhishGuard Enterprise Portal provides role-based access for managing phishing detection, reports, alerts, and metrics. Supports admin and auditor roles with secure authentication.

## Roles and Permissions
- **Admin**: Full access - manage users, alerts, reports, metrics, export for SOC.
- **Auditor**: View-only access - scan history, reports, alerts, metrics.

## Getting Started
1. Register/Login via `/api/portal/login` or `/api/portal/register`.
2. Access portal at `/portal` (frontend will show role-based UI).

## Features
### Dashboard
- **Stats**: Total scans, phishing detected, accuracy, active models.
- **Metrics**: SLA (avg scan time), alert counts, cluster summaries.
- **Conditional**: Admins see user management; auditors see read-only views.

### Alerts
- **Setup Rules**: Admins set rules (e.g., "score > 0.7" triggers email alert).
- **View Alerts**: List triggered alerts with timestamps.
- **Email Notifications**: Configured via SMTP (set env vars: SMTP_SERVER, EMAIL_USER, EMAIL_PASS).

### Reports
- **Saved Reports**: List generated takedown reports (PDFs).
- **Generate**: From scan results, export as PDF with WHOIS/abuse contacts.
- **Export**: CSV/PDF for SOC (bundled data).

### Active Learning
- **Feedback**: Mark scans as safe/phishing to update model.
- **Retraining**: Queued automatically after feedback; admins can trigger manual retrain.

## API Endpoints
- `POST /api/portal/login`: Authenticate (returns token).
- `POST /api/portal/register`: Register user (admin only for admin role).
- `GET /api/portal/dashboard`: Role-based data (stats, metrics).
- `POST /api/portal/alerts`: Set/view alerts.
- `GET /api/portal/reports`: List/export reports.
- `POST /api/portal/export_soc`: Bundle for SOC (JSON/CSV).
- `POST /api/feedback`: Submit user feedback.

## Configuration
- **API Keys**: Set `GOOGLE_SAFE_BROWSING_API_KEY` for feeds.
- **SMTP**: For email alerts/reports (SMTP_SERVER, EMAIL_USER, EMAIL_PASS).
- **DB**: SQLite auto-init; migrate if needed.
- **Celery**: For queued retraining (optional; set REDIS_URL).

## Security
- Password hashing with Werkzeug.
- Session-based auth with Flask-Login.
- No credential capture in scans (heuristics only).

## Troubleshooting
- **Login Issues**: Check DB for user; reset password via admin.
- **Feed Errors**: Verify API keys; fallback to local.
- **Retraining Fails**: Check feedback data; run manually via `python active_learning.py retrain`.
- **Reports**: Ensure reportlab installed; WHOIS may fail for some domains.

## Acceptance Criteria Fulfillment
- ≥3 feeds with timestamps: Google, PhishTank, URLhaus, OpenPhish.
- Clustering: DBSCAN on features, campaign summaries.
- Takedown Reports: PDF with evidence, WHOIS, abuse contacts, optional email submit.
- Credential Detection: Heuristics flag forms without capturing data.
- Portal: Roles (admin/auditor), alerts, saved reports, SLA metrics, export for SOC.
- Active Learning: Feedback queues retraining, updates model.
