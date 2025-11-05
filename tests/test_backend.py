import pytest
import json
from backend import app, extract_features, calculate_multi_signal_score, calculate_confidence, get_reason_codes
from threat_feeds import aggregate_feeds
from clustering import vectorize_features
from report_generator import get_whois_info
from database import init_db, query_db, insert_db
import os

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            init_db(app)  # Init DB for tests
        yield client

def test_extract_features():
    url = "https://example.com/login?user=test"
    features = extract_features(url)
    assert features is not None
    assert 'urlLength' in features
    assert features['isHttps'] == True
    assert features['hasLogin'] == True

def test_calculate_multi_signal_score():
    features = {
        'isHttps': False, 'hasIP': True, 'suspiciousKeywords': 2, 'domainAge': 10,
        'hostnameEntropy': 4.8, 'isShortened': False, 'urlLength': 100
    }
    score = calculate_multi_signal_score(features)
    assert 0 <= score <= 1
    assert score > 0.5  # Should be high for phishing-like features

def test_calculate_confidence():
    features = {'urlLength': 50, 'domainLength': 10}  # Few features
    score = 0.7
    confidence = calculate_confidence(features, score)
    assert 0 <= confidence <= 100
    assert confidence > 80  # Base + boosts

def test_get_reason_codes():
    features = {'isHttps': False, 'hasIP': True, 'suspiciousKeywords': 3}
    score = 0.8
    reasons = get_reason_codes(features, score)
    assert 'NO_HTTPS' in reasons
    assert 'USES_IP' in reasons
    assert 'HIGH_RISK_SCORE' in reasons

def test_aggregate_feeds():
    url = "https://example.com"
    result = aggregate_feeds(url)
    assert 'feeds' in result
    assert len(result['feeds']) >= 3  # At least 3 feeds
    assert 'overall_risk' in result
    assert 0 <= result['overall_risk'] <= 1

def test_vectorize_features():
    features = {'hostnameEntropy': 4.5, 'suspiciousKeywords': 2, 'urlLength': 100}
    vector = vectorize_features(features)
    assert len(vector) == 8  # As defined
    assert vector[0] == 4.5

def test_get_whois_info():
    domain = "example.com"
    info = get_whois_info(domain)
    assert 'domain' in info
    assert info['domain'] == domain
    # May have error if WHOIS fails, but structure should be there

def test_scan_endpoint(client):
    response = client.post('/api/scan', json={'url': 'https://example.com'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'url' in data
    assert 'score' in data
    assert 'feeds' in data  # New: feeds aggregated

def test_bulk_scan_endpoint(client):
    response = client.post('/api/bulk', json={'urls': ['https://example.com', 'https://test.com']})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'results' in data
    assert len(data['results']) == 2

def test_feedback_endpoint(client):
    # Mock auth if needed, but for now assume open
    response = client.post('/api/feedback', json={'url': 'https://example.com', 'label': 'phishing'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True

# Integration: Full scan with DB
def test_scan_with_db(client):
    response = client.post('/api/scan', json={'url': 'https://phishing-test.com'})
    assert response.status_code == 200
    # Check DB insertion (mock or query)
    scans = query_db('SELECT * FROM scans WHERE url = ?', ('https://phishing-test.com',))
    assert len(scans) > 0

if __name__ == '__main__':
    pytest.main()
