i# --- ML Model Integration ---
import joblib
import os
import re
from urllib.parse import urlparse, parse_qs
import ipaddress
import csv
import io
import json
from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bs4 import BeautifulSoup
import structlog
import sentry_sdk
from celery import Celery
import redis
from datetime import timedelta
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import shap
import logging
import numpy as np

# Imports for new features
from database import init_db, close_db, query_db, insert_db
from threat_feeds import aggregate_feeds_async, aggregate_feeds
from clustering import cluster_similar_scans_async, assign_cluster_to_scan, visualize_clusters
from report_generator import generate_takedown_report_async, generate_takedown_report, submit_report, get_whois_info
from auth import init_jwt, api_login, api_logout, api_register, auditor_required, admin_required, get_current_user_role, api_required, validate_session
from active_learning import retrain_model_async, submit_feedback
from config import get_config

config = get_config()
celery = None
r = None

def init_async_services():
    global celery, r
    if not app.config.get('TESTING'):  # Skip async services in test mode
        celery = Celery('backend', broker=config.REDIS_URL)
        r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None

logging.basicConfig(level=logging.INFO)

# Path to your trained model (update as needed)
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishguard_model.pkl')
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
        print('ML model loaded successfully.')
    except Exception as e:
        print(f'Error loading ML model: {e}')
else:
    print('ML model file not found. Predictions will be simulated.')

# --- Feature Extraction Logic ---
import math
import requests
from urllib.parse import unquote
import random

def is_private_ip(hostname):
    """
    Checks if a hostname is a private IP address.
    """
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private
    except ValueError:
        return False

def calculate_entropy(text):
    """
    Calculates the Shannon entropy of a string.
    """
    if not text:
        return 0
    entropy = 0
    length = len(text)
    char_count = {}
    for char in text:
        char_count[char] = char_count.get(char, 0) + 1
    for count in char_count.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def get_whois_age(domain):
    """
    Simulates WHOIS lookup to get domain age in days.
    In production, use a real WHOIS API.
    """
    # Dummy implementation: random age for simulation
    return int(random.random() * 3650)  # 0-10 years

def detect_punycode(domain):
    """
    Detects if domain uses punycode (internationalized domain names).
    Returns True if the domain contains xn-- labels or decoding changes the string.
    """
    try:
        if 'xn--' in domain:
            return True
        encoded = domain.encode('idna').decode('ascii')
        decoded = encoded.encode('ascii').decode('idna')
        return decoded != domain
    except Exception:
        return False

def check_login_form(url):
    """
    Enhanced: Fetch HTML and detect credential collection forms without capturing data.
    Flags forms with password/email inputs as potential credential collectors.
    """
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'PhishGuard/1.0'})
        if response.status_code != 200:
            return False
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            has_password = any(inp.get('type') == 'password' for inp in inputs)
            has_email = any(inp.get('type') == 'email' or 'email' in (inp.get('name') or '').lower() for inp in inputs)
            if has_password or has_email:
                return True  # Potential credential collector
        return False
    except:
        # Fallback to keyword check
        return 'login' in url.lower() or 'signin' in url.lower()

def extract_features(url):
    """
    Extracts a set of features from a given URL for phishing detection.
    """
    features = {}
    try:
        url_obj = urlparse(url)
        hostname = url_obj.hostname or ''
        pathname = url_obj.path or ''
        search = url_obj.query or ''

        # Basic URL metrics
        features['urlLength'] = len(url)
        features['domainLength'] = len(hostname)
        features['pathLength'] = len(pathname)

        # Character analysis
        features['specialChars'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>\-_=+]', url))
        features['digits'] = len(re.findall(r'\d', url))
        features['letters'] = len(re.findall(r'[a-zA-Z]', url))

        # Domain analysis
        features['subdomainCount'] = hostname.count('.') - 1 if hostname.count('.') > 0 else 0
        features['domainTokens'] = len(hostname.split('.'))
        features['hostnameEntropy'] = calculate_entropy(hostname)

        # Protocol and security
        features['isHttps'] = url.startswith('https://')
        features['hasPort'] = url_obj.port is not None
        features['portNumber'] = url_obj.port if url_obj.port else (443 if features['isHttps'] else 80)

        # Suspicious patterns
        suspicious_keywords = [
            "secure", "account", "verify", "login", "signin", "bank", "paypal", "amazon", "microsoft", "google", "apple", "update", "confirm", "suspended", "locked", "security", "alert", "warning"
        ]
        features['suspiciousKeywords'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())

        # IP address detection
        features['hasIP'] = bool(re.match(r'\d{1,3}(?:\.\d{1,3}){3}', hostname))
        features['hasPrivateIP'] = is_private_ip(hostname)

        # URL shortening services
        shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "tiny.cc", "buff.ly", "adf.ly", "is.gd", "soo.gd"
        ]
        features['isShortened'] = any(shortener in hostname for shortener in shorteners)

        # Path analysis
        features['pathDepth'] = len([p for p in pathname.split('/') if p])
        features['hasQueryParams'] = len(search) > 0
        features['queryParamsCount'] = len(parse_qs(search))

        # Suspicious path patterns
        features['hasRedirect'] = 'redirect' in pathname or 'redirect' in search or 'url=' in search
        features['hasLogin'] = 'login' in pathname or 'signin' in pathname
        features['hasSecure'] = 'secure' in pathname or 'secure' in search

        # Hex encoding detection (common in phishing)
        features['hasHex'] = bool(re.search(r'%[0-9A-Fa-f]{2}', url))

        # TLD analysis
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        suspicious_tlds = ["tk", "ml", "ga", "cf", "icu", "top", "click"]
        features['suspiciousTLD'] = tld in suspicious_tlds
        features['tld'] = tld

        # Advanced features
        features['domainAge'] = get_whois_age(hostname)
        features['hasPunycode'] = detect_punycode(hostname)
        features['hasLoginForm'] = check_login_form(url)
        features['alexa_rank'] = int(random.random() * 1000000)  # Simulated

        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None

# --- Flask App ---
app = Flask(__name__)
CORS(app)
app.secret_key = 'phishguard_secret_key'  # Change in production

# Init DB and auth
init_db(app)
init_jwt(app)

# Teardown DB
@app.teardown_appcontext
def teardown_db(exception):
    close_db()

@app.route('/api/scan', methods=['POST'])
# Public scanning endpoint to match current frontend usage. Re-enable @api_required if you want auth-only.
# @api_required
def scan_url():
    app.logger.info('Received scan request')
    data = request.get_json()
    app.logger.info(f'Request data: {data}')
    
    url = data.get('url')
    user_id = getattr(request, 'user_id', None)  # From auth, if implemented

    if not url:
        app.logger.error('URL not provided')
        return jsonify({'error': 'URL not provided'}), 400

    app.logger.info(f'Extracting features for URL: {url}')
    features = extract_features(url)
    if not features:
        app.logger.error('Failed to extract features')
        return jsonify({'error': 'Failed to extract features'}), 500
    
    app.logger.info('Features extracted successfully')

    # Aggregate feeds
    feeds_result = aggregate_feeds(url)
    feed_risk = feeds_result['overall_risk']

    # ML prediction if model loaded
    ml_prob = 0.5
    if ml_model and isinstance(ml_model, dict) and 'models' in ml_model:
        vector = [features.get(k, 0) for k in ['urlLength', 'domainLength', 'pathLength', 'specialChars', 'digits', 'letters', 'subdomainCount', 'domainTokens', 'hostnameEntropy', 'isHttps', 'hasPort', 'portNumber', 'suspiciousKeywords', 'hasIP', 'hasPrivateIP', 'isShortened', 'pathDepth', 'hasQueryParams', 'queryParamsCount', 'hasRedirect', 'hasLogin', 'hasSecure', 'hasHex', 'suspiciousTLD', 'domainAge', 'hasPunycode', 'hasLoginForm', 'alexa_rank']]
        # Ensemble prediction
        ensemble_probas = np.zeros((1, 2))
        for name, model in ml_model['models'].items():
            weight = ml_model['weights'].get(name, 0.33)
            ensemble_probas += weight * model.predict_proba([vector])
        ml_prob = ensemble_probas[0][1]
    elif ml_model and hasattr(ml_model, 'predict_proba'):
        vector = [features.get(k, 0) for k in ['urlLength', 'domainLength', 'pathLength', 'specialChars', 'digits', 'letters', 'subdomainCount', 'domainTokens', 'hostnameEntropy', 'isHttps', 'hasPort', 'portNumber', 'suspiciousKeywords', 'hasIP', 'hasPrivateIP', 'isShortened', 'pathDepth', 'hasQueryParams', 'queryParamsCount', 'hasRedirect', 'hasLogin', 'hasSecure', 'hasHex', 'suspiciousTLD', 'domainAge', 'hasPunycode', 'hasLoginForm', 'alexa_rank']]
        ml_prob = ml_model.predict_proba([vector])[0][1]

    # Ensemble score: weighted avg of heuristic and ML
    heuristic_score = calculate_multi_signal_score(features)
    ensemble_score = (heuristic_score * 0.6) + (ml_prob * 0.4) + (feed_risk * 0.1)
    ensemble_score = min(ensemble_score, 1.0)

    confidence = calculate_confidence(features, ensemble_score)
    # Normalize confidence to 0-1 for API response consistency with frontend expectations
    confidence_normalized = max(0.0, min(1.0, confidence / 100.0))
    reason_codes = get_reason_codes(features, ensemble_score)

    # Clustering
    cluster_id = assign_cluster_to_scan(url, features)
    cluster_summary = None
    if cluster_id:
        cluster_data = query_db('SELECT summary FROM clusters WHERE id = ?', (cluster_id,), one=True)
        cluster_summary = cluster_data['summary'] if cluster_data else None

    prediction = ensemble_score > 0.5
    model_name = 'Ensemble ML + Feeds'

    result = {
        'url': url,
        'phishing': bool(prediction),
        'score': float(ensemble_score),
        'confidence': float(confidence_normalized),
        'reason_codes': reason_codes,
        'features': features,
        'model': model_name,
        'feeds': feeds_result['feeds'],
        'cluster': {'id': cluster_id, 'summary': cluster_summary} if cluster_id else None,
        'credentialLeakRisk': bool(features.get('hasLoginForm', False))
    }

    # Save to DB
    insert_db('INSERT INTO scans (url, phishing, score, confidence, reason_codes, features, model, user_id, cluster_id, feeds_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              (url, prediction, ensemble_score, confidence, json.dumps(reason_codes), json.dumps(features), model_name, user_id, cluster_id, json.dumps(feeds_result['feeds'])))

    return jsonify(result)

def calculate_multi_signal_score(features):
    """
    Calculate phishing score using multi-signal approach with weighted features.
    """
    score = 0.0

    # Domain signals (weight: 0.3)
    domain_score = 0
    if features.get('hasIP', False): domain_score += 0.4
    if features.get('hasPrivateIP', False): domain_score += 0.3
    if features.get('suspiciousTLD', False): domain_score += 0.2
    if features.get('hasPunycode', False): domain_score += 0.3
    if features.get('domainAge', 365) < 30: domain_score += 0.3
    if features.get('hostnameEntropy', 0) > 4.5: domain_score += 0.2
    score += domain_score * 0.3

    # URL signals (weight: 0.25)
    url_score = 0
    if not features.get('isHttps', False): url_score += 0.3
    if features.get('isShortened', False): url_score += 0.4
    if features.get('hasHex', False): url_score += 0.3
    if features.get('urlLength', 0) > 75: url_score += 0.2
    if features.get('subdomainCount', 0) > 3: url_score += 0.2
    score += url_score * 0.25

    # Content signals (weight: 0.25)
    content_score = 0
    if features.get('suspiciousKeywords', 0) > 0: content_score += min(features['suspiciousKeywords'] * 0.1, 0.4)
    if features.get('hasLoginForm', False): content_score += 0.3
    if features.get('hasRedirect', False): content_score += 0.3
    if features.get('hasSecure', False): content_score += 0.2
    score += content_score * 0.25

    # SSL/Content signals (weight: 0.2)
    ssl_score = 0
    if features.get('hasPort', False) and features.get('portNumber', 80) not in [80, 443]: ssl_score += 0.3
    if features.get('pathDepth', 0) > 5: ssl_score += 0.2
    if features.get('queryParamsCount', 0) > 5: ssl_score += 0.2
    score += ssl_score * 0.2

    return min(score, 1.0)

def calculate_confidence(features, score):
    """
    Calculate confidence score (0-100) based on feature reliability.
    """
    base_confidence = 80  # Base confidence

    # Increase confidence with more features
    feature_count = len([f for f in features.values() if f is not None])
    confidence_boost = min(feature_count * 2, 15)

    # Adjust based on score certainty
    if score < 0.3 or score > 0.7:
        certainty_boost = 10
    else:
        certainty_boost = 0

    return min(base_confidence + confidence_boost + certainty_boost, 100)

def get_reason_codes(features, score):
    """
    Generate key reason codes for the prediction.
    """
    reasons = []

    if not features.get('isHttps', False):
        reasons.append("NO_HTTPS")
    if features.get('hasIP', False):
        reasons.append("USES_IP")
    if features.get('isShortened', False):
        reasons.append("SHORTENED_URL")
    if features.get('suspiciousKeywords', 0) > 0:
        reasons.append("SUSPICIOUS_KEYWORDS")
    if features.get('suspiciousTLD', False):
        reasons.append("SUSPICIOUS_TLD")
    if features.get('hasPunycode', False):
        reasons.append("PUNYCODE_DOMAIN")
    if features.get('domainAge', 365) < 30:
        reasons.append("NEW_DOMAIN")
    if features.get('hasLoginForm', False):
        reasons.append("LOGIN_FORM_DETECTED")

    if score < 0.3:
        reasons.append("LOW_RISK_SCORE")
    elif score > 0.7:
        reasons.append("HIGH_RISK_SCORE")

    return reasons[:5]  # Limit to top 5 reasons

@app.route('/api/bulk', methods=['POST'])
@api_required
def bulk_scan():
    """Bulk scan endpoint for processing multiple URLs"""
    try:
        app.logger.info('Received bulk scan request')
        data = request.get_json()
        app.logger.info(f'Request data: {data}')
        
        # Check for auth token
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            app.logger.error('No Authorization header present')
            return jsonify({'error': 'No Authorization header'}), 401
        
        if not data:
            app.logger.error('No data provided')
            return jsonify({'error': 'No data provided'}), 422
            
        urls = data.get('urls', [])
        app.logger.info(f'URLs to scan: {urls}')
        
        if not isinstance(urls, list):
            app.logger.error(f'URLs must be a list, got {type(urls)}')
            return jsonify({'error': 'URLs must be a list'}), 422
            
        if not urls:
            app.logger.error('Empty URLs list')
            return jsonify({'error': 'Empty URLs list'}), 422
            
        # Validate URLs
        for url in urls:
            if not isinstance(url, str):
                app.logger.error(f'Invalid URL format: {url} is not a string')
                return jsonify({'error': f'Invalid URL format: {url} is not a string'}), 422
            if not url.startswith(('http://', 'https://')):
                app.logger.error(f'Invalid URL format: {url} must start with http:// or https://')
                return jsonify({'error': f'Invalid URL format: {url} must start with http:// or https://'}), 422
        
        # Validate URLs
        for url in urls:
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                return jsonify({'error': f'Invalid URL format: {url}'}), 422
        
        results = []
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    for url in urls:
        # Reuse scan logic (simplified, without full ensemble for brevity)
        features = extract_features(url)
        if features:
            feeds_result = aggregate_feeds(url)
            feed_risk = feeds_result['overall_risk']
            heuristic_score = calculate_multi_signal_score(features)
            ensemble_score = (heuristic_score * 0.6) + (feed_risk * 0.4)  # Simplified
            confidence = calculate_confidence(features, ensemble_score)
            confidence_normalized = max(0.0, min(1.0, confidence / 100.0))
            reason_codes = get_reason_codes(features, ensemble_score)
            prediction = ensemble_score > 0.5
            cluster_id = assign_cluster_to_scan(url, features)

            result = {
                'url': url,
                'phishing': bool(prediction),
                'score': float(ensemble_score),
                'confidence': float(confidence_normalized),
                'reason_codes': reason_codes,
                'feeds': feeds_result['feeds'],
                'cluster': cluster_id
            }
            # Save to DB
            insert_db('INSERT INTO scans (url, phishing, score, confidence, reason_codes, feeds_data) VALUES (?, ?, ?, ?, ?, ?)',
                      (url, prediction, ensemble_score, confidence, json.dumps(reason_codes), json.dumps(feeds_result['feeds'])))
        else:
            result = {'url': url, 'error': 'Failed to extract features'}
        results.append(result)
    return jsonify({'results': results})

@app.route('/api/history', methods=['GET'])
@auditor_required
def get_history():
    user_role = get_current_user_role()
    limit = int(request.args.get('limit', 50))
    scans = query_db('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    history = []
    for scan in scans:
        history.append({
            'id': scan['id'],
            'url': scan['url'],
            'phishing': scan['phishing'],
            'score': scan['score'],
            'timestamp': scan['timestamp'],
            'cluster_id': scan['cluster_id'],
            'feeds_data': json.loads(scan['feeds_data']) if scan['feeds_data'] else []
        })
    return jsonify({'history': history})

@app.route('/api/history/export', methods=['GET'])
@auditor_required
def export_history():
    scans = query_db('SELECT url, phishing, score, timestamp FROM scans')
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['url', 'phishing', 'score', 'timestamp'])
    writer.writeheader()
    for scan in scans:
        writer.writerow(scan)
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='scan_history.csv')

@app.route('/api/whois', methods=['POST'])
@auditor_required
def whois_lookup():
    data = request.get_json()
    url = data.get('url')
    domain = urlparse(url).netloc
    whois_info = get_whois_info(domain)  # From report_generator
    return jsonify(whois_info)

@app.route('/api/google_safe_browsing', methods=['POST'])
@auditor_required
def google_safe_browsing():
    data = request.get_json()
    url = data.get('url')
    from threat_feeds import fetch_google_safe_browsing
    result = fetch_google_safe_browsing(url)
    return jsonify(result)

@app.route('/api/report/generate', methods=['POST'])
@auditor_required
def generate_report():
    data = request.get_json()
    url = data.get('url')
    export = data.get('export', 'json')  # json or pdf
    # Fetch scan data from DB
    scan = query_db('SELECT * FROM scans WHERE url = ? ORDER BY timestamp DESC LIMIT 1', (url,), one=True)
    if not scan:
        return jsonify({'error': 'No scan data found'}), 404
    scan_data = {
        'url': scan['url'],
        'score': scan['score'],
        'reasons': json.loads(scan['reason_codes']),
        'features': json.loads(scan['features']),
        'feeds': json.loads(scan['feeds_data']),
        'timestamp': scan['timestamp']
    }
    if export == 'pdf':
        buffer = generate_takedown_report(scan_data)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f'report_{url.replace("/", "_")}.pdf')
    return jsonify(scan_data)

@app.route('/api/feedback', methods=['POST'])
@auditor_required
def submit_feedback():
    try:
        app.logger.info('Received feedback request')
        data = request.get_json()
        app.logger.info(f'Feedback data: {data}')
        
        if not data:
            app.logger.error('No data provided')
            return jsonify({'error': 'No data provided'}), 422
            
        url = data.get('url')
        user_label = data.get('label')  # 'phishing' or 'safe'
        app.logger.info(f'Processing feedback - URL: {url}, Label: {user_label}')
        
        # Validate input
        if not url or not user_label:
            app.logger.error('Missing URL or label')
            return jsonify({'error': 'URL and label are required'}), 422
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
            app.logger.error(f'Invalid URL format: {url}')
            return jsonify({'error': 'Invalid URL format'}), 422
        if user_label not in ['phishing', 'safe']:
            app.logger.error(f'Invalid label: {user_label}')
            return jsonify({'error': 'Label must be either "phishing" or "safe"'}), 422
        
        user_id = getattr(request, 'user_id', None)
        insert_db('INSERT INTO feedback (url, user_label, user_id) VALUES (?, ?, ?)', (url, user_label, user_id))
        
        # Only queue retrain if not in testing mode
        if not app.config.get('TESTING') and celery:
            retrain_model_async.delay()
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    retrain_model_async.delay()
    return jsonify({'success': True})

# Portal endpoints
@app.route('/api/portal/login', methods=['POST'])
def portal_login():
    return api_login()

@app.route('/api/portal/logout', methods=['POST'])
def portal_logout():
    return api_logout()

@app.route('/api/portal/register', methods=['POST'])
@admin_required
def portal_register():
    return api_register()

@app.route('/api/portal/dashboard', methods=['GET'])
@auditor_required
def portal_dashboard():
    user_role = get_current_user_role()
    total_scans = query_db('SELECT COUNT(*) as count FROM scans', one=True)['count']
    phishing_count = query_db('SELECT COUNT(*) as count FROM scans WHERE phishing = 1', one=True)['count']
    avg_score = query_db('SELECT AVG(score) as avg FROM scans', one=True)['avg'] or 0
    ml_models = query_db('SELECT COUNT(*) as count FROM model_versions', one=True)['count']
    clusters = query_db('SELECT * FROM clusters ORDER BY timestamp DESC LIMIT 5')
    alerts = query_db('SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 10')
    return jsonify({
        'stats': {'total_scans': total_scans, 'phishing_detected': phishing_count, 'avg_score': avg_score, 'ml_models': ml_models},
        'clusters': [{'id': c['id'], 'summary': c['summary']} for c in clusters],
        'alerts': [{'rule': a['rule'], 'message': a['message'], 'triggered_at': a['triggered_at']} for a in alerts],
        'role': user_role
    })

@app.route('/api/portal/alerts', methods=['POST'])
@admin_required
def set_alert():
    data = request.get_json()
    rule = data.get('rule')  # e.g., 'score > 0.7'
    message = data.get('message')
    insert_db('INSERT INTO alerts (rule, message) VALUES (?, ?)', (rule, message))
    return jsonify({'success': True})

@app.route('/api/portal/reports', methods=['GET'])
@auditor_required
def list_reports():
    reports = query_db('SELECT id, url, score, timestamp FROM scans WHERE phishing = 1 ORDER BY timestamp DESC LIMIT 20')
    return jsonify({'reports': [{'id': r['id'], 'url': r['url'], 'score': r['score'], 'timestamp': r['timestamp']} for r in reports]})

@app.route('/api/portal/export_soc', methods=['GET'])
@admin_required
def export_soc():
    # Bundle recent scans, clusters, alerts as JSON/CSV
    data = {
        'scans': query_db('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 100'),
        'clusters': query_db('SELECT * FROM clusters'),
        'alerts': query_db('SELECT * FROM alerts')
    }
    output = io.StringIO()
    json.dump(data, output)
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='application/json', as_attachment=True, download_name='soc_export.json')

if __name__ == '__main__':
    app.run(debug=True)