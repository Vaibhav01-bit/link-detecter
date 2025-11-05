import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np
import pandas as pd
import random
import math
from urllib.parse import urlparse
import re
import os
import json
from database import query_db, init_db
from flask import Flask

# Generate synthetic dataset
def generate_synthetic_data(n_samples=10000):
    """
    Generate synthetic URL data for training.
    """
    urls = []
    labels = []
    features = []

    # Phishing URLs
    phishing_patterns = [
        "http://secure-login-{}.com/update",
        "https://bankofamerica-login.com/verify",
        "http://paypal-support.com/confirm",
        "http://amazon-account.com/security",
        "http://microsoft365-login.com/suspended",
        "http://google-account-recovery.com/alert",
        "http://appleid-support.com/locked",
        "http://netflix-billing.com/update",
        "http://ebay-signin.com/verify",
        "http://irs-gov.com/taxrefund"
    ]

    benign_patterns = [
        "https://www.google.com/search",
        "https://www.wikipedia.org/",
        "https://www.github.com/",
        "https://www.stackoverflow.com/",
        "https://www.youtube.com/watch",
        "https://www.amazon.com/",
        "https://www.facebook.com/",
        "https://www.twitter.com/",
        "https://www.linkedin.com/",
        "https://www.reddit.com/"
    ]

    for _ in range(n_samples // 2):
        # Phishing
        pattern = random.choice(phishing_patterns)
        url = pattern.format(random.randint(1000, 9999))
        urls.append(url)
        labels.append(1)  # Phishing

        # Generate features (simplified)
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        features_dict = {
            'urlLength': len(url),
            'domainLength': len(hostname),
            'pathLength': len(parsed.path),
            'specialChars': len(re.findall(r'[!@#$%^&*(),.?":{}|<>\-_=+]', url)),
            'digits': len(re.findall(r'\d', url)),
            'letters': len(re.findall(r'[a-zA-Z]', url)),
            'subdomainCount': hostname.count('.') - 1 if hostname.count('.') > 0 else 0,
            'domainTokens': len(hostname.split('.')),
            'hostnameEntropy': 3.5 + random.uniform(-0.5, 0.5),  # Higher entropy for phishing
            'isHttps': 1 if url.startswith('https') else 0,
            'hasPort': 0,
            'portNumber': 443 if url.startswith('https') else 80,
            'suspiciousKeywords': random.randint(1, 3),
            'hasIP': 0,
            'hasPrivateIP': 0,
            'isShortened': 0,
            'pathDepth': len([p for p in parsed.path.split('/') if p]),
            'hasQueryParams': 1 if parsed.query else 0,
            'queryParamsCount': len(parsed.query.split('&')) if parsed.query else 0,
            'hasRedirect': random.choice([0, 1]),
            'hasLogin': 1 if 'login' in url.lower() else 0,
            'hasSecure': 1 if 'secure' in url.lower() else 0,
            'hasHex': random.choice([0, 1]),
            'suspiciousTLD': 1 if hostname.endswith(('.tk', '.ml', '.ga')) else 0,
            'domainAge': random.randint(1, 30),  # New domains
            'hasPunycode': random.choice([0, 1]),
            'hasLoginForm': 1,
            'alexa_rank': random.randint(100000, 1000000)
        }
        features.append([features_dict[k] for k in sorted(features_dict.keys())])

    for _ in range(n_samples // 2):
        # Benign
        pattern = random.choice(benign_patterns)
        url = pattern + random.choice(["?q=search", "", "/page/1"])
        urls.append(url)
        labels.append(0)  # Benign

        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        features_dict = {
            'urlLength': len(url),
            'domainLength': len(hostname),
            'pathLength': len(parsed.path),
            'specialChars': len(re.findall(r'[!@#$%^&*(),.?":{}|<>\-_=+]', url)),
            'digits': len(re.findall(r'\d', url)),
            'letters': len(re.findall(r'[a-zA-Z]', url)),
            'subdomainCount': hostname.count('.') - 1 if hostname.count('.') > 0 else 0,
            'domainTokens': len(hostname.split('.')),
            'hostnameEntropy': 3.0 + random.uniform(-0.5, 0.5),
            'isHttps': 1,
            'hasPort': 0,
            'portNumber': 443,
            'suspiciousKeywords': 0,
            'hasIP': 0,
            'hasPrivateIP': 0,
            'isShortened': 0,
            'pathDepth': len([p for p in parsed.path.split('/') if p]),
            'hasQueryParams': random.choice([0, 1]),
            'queryParamsCount': len(parsed.query.split('&')) if parsed.query else 0,
            'hasRedirect': 0,
            'hasLogin': 0,
            'hasSecure': 0,
            'hasHex': 0,
            'suspiciousTLD': 0,
            'domainAge': random.randint(365, 3650),
            'hasPunycode': 0,
            'hasLoginForm': 0,
            'alexa_rank': random.randint(1, 10000)
        }
        features.append([features_dict[k] for k in sorted(features_dict.keys())])

    return urls, labels, features

def load_feedback_data():
    """
    Load user feedback from DB for active learning.
    """
    app = Flask(__name__)
    init_db(app)
    with app.app_context():
        feedback = query_db('SELECT url, user_label FROM feedback')
        feedback_data = []
        for f in feedback:
            label = 1 if f['user_label'] == 'phishing' else 0
            # Generate features from URL (simplified, in production use stored features)
            features = extract_features(f['url'])  # Assume extract_features is available
            if features:
                feature_vector = [features[k] for k in sorted(features.keys())]
                feedback_data.append((f['url'], label, feature_vector))
        return feedback_data

def augment_with_feedback(synthetic_data, feedback_data, balance_ratio=0.5):
    """
    Augment synthetic data with feedback, balancing classes.
    """
    urls, labels, features = synthetic_data
    feedback_urls, feedback_labels, feedback_features = zip(*feedback_data) if feedback_data else ([], [], [])

    # Balance: add feedback to minority class
    phishing_count = sum(labels)
    benign_count = len(labels) - phishing_count
    if phishing_count < benign_count:
        # Add more phishing from feedback
        phishing_feedback = [(u, l, f) for u, l, f in zip(feedback_urls, feedback_labels, feedback_features) if l == 1]
        add_count = min(len(phishing_feedback), int((benign_count - phishing_count) * balance_ratio))
        for i in range(add_count):
            urls.append(phishing_feedback[i][0])
            labels.append(1)
            features.append(phishing_feedback[i][2])
    elif benign_count < phishing_count:
        # Add more benign from feedback
        benign_feedback = [(u, l, f) for u, l, f in zip(feedback_urls, feedback_labels, feedback_features) if l == 0]
        add_count = min(len(benign_feedback), int((phishing_count - benign_count) * balance_ratio))
        for i in range(add_count):
            urls.append(benign_feedback[i][0])
            labels.append(0)
            features.append(benign_feedback[i][2])

    return urls, labels, features

def retrain_model():
    """
    Retrain the model with synthetic + feedback data.
    """
    # Load feedback
    feedback_data = load_feedback_data()

    # Generate synthetic
    synthetic_data = generate_synthetic_data(10000)

    # Augment
    augmented_data = augment_with_feedback(synthetic_data, feedback_data)

    # Create DataFrame
    feature_names = [
        'urlLength', 'domainLength', 'pathLength', 'specialChars', 'digits', 'letters',
        'subdomainCount', 'domainTokens', 'hostnameEntropy', 'isHttps', 'hasPort', 'portNumber',
        'suspiciousKeywords', 'hasIP', 'hasPrivateIP', 'isShortened', 'pathDepth', 'hasQueryParams',
        'queryParamsCount', 'hasRedirect', 'hasLogin', 'hasSecure', 'hasHex', 'suspiciousTLD',
        'domainAge', 'hasPunycode', 'hasLoginForm', 'alexa_rank'
    ]
    df = pd.DataFrame(augmented_data[2], columns=feature_names)
    df['label'] = augmented_data[1]

    # Split data
    X = df.drop('label', axis=1)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f'Accuracy: {accuracy:.4f}')
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(model, 'phishguard_model.pkl')
    print('Model retrained and saved as phishguard_model.pkl')

if __name__ == '__main__':
    retrain_model()
