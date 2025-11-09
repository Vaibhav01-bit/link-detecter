import requests
import json
import time
from urllib.parse import urlparse
import os
import redis
from config import get_config
from celery import Celery
import logging

config = get_config()
celery = Celery('threat_feeds', broker=config.REDIS_URL)
r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None
logging.basicConfig(level=logging.INFO)

CACHE_DURATION = 3600  # 1 hour

def get_cache_key(feed_name, url):
    return f'{feed_name}_{hash(url) % 1000000}'

@celery.task
def aggregate_feeds_async(url):
    """
    Async task to aggregate threat feeds for a URL.
    """
    try:
        result = aggregate_feeds(url)
        logging.info(f"Aggregated feeds for {url}: risk {result['overall_risk']:.2f}")
        return result
    except Exception as e:
        logging.error(f"Feed aggregation failed for {url}: {str(e)}")
        return {'feeds': [], 'overall_risk': 0.0, 'error': str(e)}

def fetch_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API.
    Requires API key (set in environment or config).
    Returns: {'threat_type': str or None, 'timestamp': int}
    """
    api_key = config.GOOGLE_SAFE_BROWSING_API_KEY or os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        return {'threat_type': None, 'timestamp': int(time.time()), 'error': 'API key not set'}

    cache_key = get_cache_key('gsb', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for GSB: {cache_error}")
            cached = None
    if cached:
        return json.loads(cached)

    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        'client': {'clientId': 'phishguard', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        data = response.json()
        threat_type = data.get('matches', [{}])[0].get('threatType') if data.get('matches') else None
        result = {'threat_type': threat_type, 'timestamp': int(time.time())}
        if r:
            try:
                r.setex(cache_key, CACHE_DURATION, json.dumps(result))
            except Exception as set_error:
                logging.warning(f"Redis set error for GSB: {set_error}")
        return result
    except Exception as e:
        return {'threat_type': None, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_phishtank(url):
    """
    Check URL against PhishTank API (free, no key needed).
    Returns: {'phishing': bool, 'timestamp': int}
    """
    cache_key = get_cache_key('pt', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for PhishTank: {cache_error}")
            cached = None
    if cached:
        return json.loads(cached)

    try:
        response = requests.get('http://data.phishtank.com/data/online-valid.json', timeout=10)
        data = response.json()
        phishing = any(entry['url'] == url for entry in data)
        result = {'phishing': phishing, 'timestamp': int(time.time())}
        if r:
            try:
                r.setex(cache_key, CACHE_DURATION, json.dumps(result))
            except Exception as set_error:
                logging.warning(f"Redis set error for PhishTank: {set_error}")
        return result
    except Exception as e:
        return {'phishing': False, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_urlhaus(url):
    """
    Check URL against URLhaus blocklist (free API).
    Returns: {'blacklisted': bool, 'timestamp': int}
    """
    cache_key = get_cache_key('uh', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for URLhaus: {cache_error}")
            cached = None
    if cached:
        return json.loads(cached)

    try:
        response = requests.get('https://urlhaus-api.abuse.ch/v1/url/', params={'url': url}, timeout=10)
        data = response.json()
        blacklisted = data.get('query_status') == 'ok' and data.get('blacklists', {}).get('spamhaus_dbl', 'not listed') != 'not listed'
        result = {'blacklisted': blacklisted, 'timestamp': int(time.time())}
        if r:
            try:
                r.setex(cache_key, CACHE_DURATION, json.dumps(result))
            except Exception as set_error:
                logging.warning(f"Redis set error for URLhaus: {set_error}")
        return result
    except Exception as e:
        return {'blacklisted': False, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_virustotal(url):
    """
    Check URL against VirusTotal API.
    Requires API key.
    Returns: {'malicious': bool, 'risk_score': float, 'timestamp': int}
    """
    api_key = config.VIRUSTOTAL_API_KEY or os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {'malicious': False, 'risk_score': 0.0, 'timestamp': int(time.time()), 'error': 'API key not set'}

    cache_key = get_cache_key('vt', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for VirusTotal: {cache_error}")
            cached = None
    if cached:
        return json.loads(cached)

    try:
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers={'x-apikey': api_key}, data={'url': url}, timeout=10)
        data = response.json()
        scan_id = data.get('data', {}).get('id')
        if scan_id:
            # Get analysis
            analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers={'x-apikey': api_key}, timeout=10)
            analysis_data = analysis_response.json()
            stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0) > 0
            risk_score = stats.get('malicious', 0) / (stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious', 0) + 1e-8)
            result = {'malicious': malicious, 'risk_score': risk_score, 'timestamp': int(time.time())}
        else:
            result = {'malicious': False, 'risk_score': 0.0, 'timestamp': int(time.time())}
        if r:
            try:
                r.setex(cache_key, CACHE_DURATION, json.dumps(result))
            except Exception as set_error:
                logging.warning(f"Redis set error for VirusTotal: {set_error}")
        return result
    except Exception as e:
        return {'malicious': False, 'risk_score': 0.0, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_urlscan(url):
    """
    Check URL against URLScan.io API (free tier).
    Returns: {'risk_score': float, 'timestamp': int}
    """
    cache_key = get_cache_key('us', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for URLScan: {cache_error}")
            cached = None
    if cached:
        return json.loads(cached)

    try:
        response = requests.get('https://urlscan.io/api/v1/search/', params={'q': url}, timeout=10)
        data = response.json()
        if data.get('results'):
            # Simple heuristic: if any result, assume risk
            risk_score = 0.5 if data['results'] else 0.0
        else:
            risk_score = 0.0
        result = {'risk_score': risk_score, 'timestamp': int(time.time())}
        if r:
            try:
                r.setex(cache_key, CACHE_DURATION, json.dumps(result))
            except Exception as set_error:
                logging.warning(f"Redis set error for URLScan: {set_error}")
        return result
    except Exception as e:
        return {'risk_score': 0.0, 'timestamp': int(time.time()), 'error': str(e)}

def aggregate_feeds(url):
    """
    Aggregate results from ≥5 feeds with timestamps and Redis caching.
    Returns: {'feeds': list of dicts, 'overall_risk': float (0-1)}
    """
    feeds = [
        {'name': 'Google Safe Browsing', 'data': fetch_google_safe_browsing(url), 'weight': 0.25},
        {'name': 'PhishTank', 'data': fetch_phishtank(url), 'weight': 0.15},
        {'name': 'URLhaus', 'data': fetch_urlhaus(url), 'weight': 0.1},
        {'name': 'VirusTotal', 'data': fetch_virustotal(url), 'weight': 0.3},
        {'name': 'URLScan', 'data': fetch_urlscan(url), 'weight': 0.1}
    ]
    # Additional feed: OpenPhish (free, no key)
    cache_key = get_cache_key('openphish', url)
    cached = None
    if r:
        try:
            cached = r.get(cache_key)
        except Exception as cache_error:
            logging.warning(f"Redis cache error for OpenPhish: {cache_error}")
            cached = None
    if cached:
        openphish_data = json.loads(cached)
    else:
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=10)
            response.raise_for_status()
            openphish_urls = set(response.text.splitlines())
            phishing = url in openphish_urls
            openphish_data = {'phishing': phishing, 'timestamp': int(time.time())}
            if r:
                try:
                    r.setex(cache_key, CACHE_DURATION, json.dumps(openphish_data))
                except Exception as set_error:
                    logging.warning(f"Redis set error for OpenPhish: {set_error}")
        except Exception as e:
            openphish_data = {'phishing': False, 'timestamp': int(time.time()), 'error': str(e)}
            if r:
                try:
                    r.setex(cache_key, CACHE_DURATION, json.dumps(openphish_data))
                except Exception as set_error:
                    logging.warning(f"Redis set error for OpenPhish error: {set_error}")
    if not r:
        openphish_data = {'phishing': False, 'timestamp': int(time.time()), 'error': 'Redis not available'}
    feeds.append({'name': 'OpenPhish', 'data': openphish_data, 'weight': 0.1})

    # Calculate weighted overall risk
    weighted_risk = 0.0
    total_weight = 0.0
    for feed in feeds:
        data = feed['data']
        weight = feed['weight']
        risk = 0.0
        if 'threat_type' in data and data['threat_type']:
            risk = 1.0
        elif data.get('phishing', False) or data.get('blacklisted', False) or data.get('malicious', False):
            risk = 1.0
        elif 'risk_score' in data:
            risk = data['risk_score']
        weighted_risk += risk * weight
        total_weight += weight

    overall_risk = weighted_risk / total_weight if total_weight > 0 else 0.0

    return {'feeds': feeds, 'overall_risk': overall_risk}
