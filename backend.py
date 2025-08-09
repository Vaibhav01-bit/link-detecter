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
def is_private_ip(hostname):
    """
    Checks if a hostname is a private IP address.
    """
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private
    except ValueError:
        return False

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

        # TLD analysis
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        suspicious_tlds = ["tk", "ml", "ga", "cf", "icu", "top", "click"]
        features['suspiciousTLD'] = tld in suspicious_tlds
        features['tld'] = tld

        # Dummy values for features not easily extracted
        features['domainAge'] = 0 
        features['alexa_rank'] = 0 
        
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

    prediction = False
    model_name = 'Simulated'
    if ml_model:
        try:
            # The model expects a list of features in a specific order.
            # We'll create a reproducible feature order to avoid errors.
            feature_order = sorted(features.keys()) 
            X = [[features.get(k, 0) for k in feature_order]]
            prediction = bool(ml_model.predict(X)[0])
            model_name = type(ml_model).__name__
        except Exception as e:
            print(f'Prediction error: {e}')
            # Fallback to a safe simulated prediction
            prediction = False
            model_name = 'Simulated'

    result = {
        'url': url,
        'phishing': prediction,
        'features': features,
        'model': model_name
    }
    scan_history.append(result)
    return jsonify(result)

@app.route('/api/scan/bulk', methods=['POST'])
def bulk_scan():
    data = request.get_json()
    urls = data.get('urls', [])
    results = []
    for url in urls:
        features = extract_features(url)
        prediction = False
        model_name = 'Simulated'
        if ml_model and features:
            try:
                feature_order = sorted(features.keys())
                X = [[features.get(k, 0) for k in feature_order]]
                prediction = bool(ml_model.predict(X)[0])
                model_name = type(ml_model).__name__
            except Exception as e:
                print(f'Prediction error during bulk scan: {e}')
        
        result = {
            'url': url,
            'phishing': prediction,
            'features': features,
            'model': model_name
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