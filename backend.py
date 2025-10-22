# --- ML Model Integration ---
import joblib
import os
import re
from urllib.parse import urlparse, parse_qs
import ipaddress
import csv
import io
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

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
    return int(math.random() * 3650)  # 0-10 years

def detect_punycode(domain):
    """
    Detects if domain uses punycode (internationalized domain names).
    """
    try:
        encoded = domain.encode('idna')
        decoded = encoded.decode('idna')
        return encoded != decoded.encode('utf-8')
    except:
        return False

def check_login_form(url):
    """
    Simulates checking for login forms by looking for common patterns.
    In production, fetch and parse HTML.
    """
    # Dummy: check if URL contains login-related keywords
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
        features['alexa_rank'] = int(math.random() * 1000000)  # Simulated

        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None

# --- Flask App ---
app = Flask(__name__)
CORS(app)

# In-memory scan history (replace with DB in production)
scan_history = []

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL not provided'}), 400

    features = extract_features(url)
    if not features:
        return jsonify({'error': 'Failed to extract features'}), 500

    # Multi-signal scoring
    score = calculate_multi_signal_score(features)
    confidence = calculate_confidence(features, score)
    reason_codes = get_reason_codes(features, score)

    prediction = score > 0.5
    model_name = 'Multi-Signal Ensemble'

    result = {
        'url': url,
        'phishing': prediction,
        'score': score,
        'confidence': confidence,
        'reason_codes': reason_codes,
        'features': features,
        'model': model_name
    }
    scan_history.append(result)
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

@app.route('/api/scan/bulk', methods=['POST'])
def bulk_scan():
    data = request.get_json()
    urls = data.get('urls', [])
    results = []
    for url in urls:
        features = extract_features(url)
        if features:
            score = calculate_multi_signal_score(features)
            confidence = calculate_confidence(features, score)
            reason_codes = get_reason_codes(features, score)
            prediction = score > 0.5
            model_name = 'Multi-Signal Ensemble'

            result = {
                'url': url,
                'phishing': prediction,
                'score': score,
                'confidence': confidence,
                'reason_codes': reason_codes,
                'features': features,
                'model': model_name
            }
        else:
            result = {
                'url': url,
                'error': 'Failed to extract features'
            }
        scan_history.append(result)
        results.append(result)
    return jsonify({'results': results})

@app.route('/api/history/export', methods=['GET'])
def export_history():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['url', 'phishing', 'model'])
    writer.writeheader()
    for entry in scan_history:
        writer.writerow({k: entry.get(k, '') for k in ['url', 'phishing', 'model']})
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='scan_history.csv')

@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json()
    url = data.get('url')
    # Implement real WHOIS lookup here
    return jsonify({'url': url, 'domain_age': 365})  # Dummy value

@app.route('/api/google_safe_Browse', methods=['POST'])
def google_safe_Browse():
    data = request.get_json()
    url = data.get('url')
    # Implement Google Safe Browse API check here
    return jsonify({'url': url, 'safe': True})  # Dummy value

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Implement real authentication here
    if username == 'admin' and password == 'password':
        return jsonify({'success': True, 'token': 'dummy-token'})
    return jsonify({'success': False}), 401

if __name__ == '__main__':
    app.run(debug=True)