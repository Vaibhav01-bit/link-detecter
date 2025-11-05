import requests
import json
import time
from urllib.parse import urlparse
import os

# Cache for feeds to avoid repeated fetches (in-memory, could use Redis for production)
feed_cache = {}
CACHE_DURATION = 3600  # 1 hour

def fetch_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API.
    Requires API key (set in environment or config).
    Returns: {'threat_type': str or None, 'timestamp': int}
    """
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        return {'threat_type': None, 'timestamp': int(time.time()), 'error': 'API key not set'}

    cache_key = f'gsb_{url}'
    if cache_key in feed_cache and time.time() - feed_cache[cache_key]['timestamp'] < CACHE_DURATION:
        return feed_cache[cache_key]

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
        feed_cache[cache_key] = result
        return result
    except Exception as e:
        return {'threat_type': None, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_phishtank(url):
    """
    Check URL against PhishTank API (free, no key needed).
    Returns: {'phishing': bool, 'timestamp': int}
    """
    cache_key = f'pt_{url}'
    if cache_key in feed_cache and time.time() - feed_cache[cache_key]['timestamp'] < CACHE_DURATION:
        return feed_cache[cache_key]

    try:
        response = requests.get('http://data.phishtank.com/data/online-valid.json', timeout=10)
        data = response.json()
        phishing = any(entry['url'] == url for entry in data)
        result = {'phishing': phishing, 'timestamp': int(time.time())}
        feed_cache[cache_key] = result
        return result
    except Exception as e:
        return {'phishing': False, 'timestamp': int(time.time()), 'error': str(e)}

def fetch_urlhaus(url):
    """
    Check URL against URLhaus blocklist (free API).
    Returns: {'blacklisted': bool, 'timestamp': int}
    """
    cache_key = f'uh_{url}'
    if cache_key in feed_cache and time.time() - feed_cache[cache_key]['timestamp'] < CACHE_DURATION:
        return feed_cache[cache_key]

    try:
        response = requests.get('https://urlhaus-api.abuse.ch/v1/url/', params={'url': url}, timeout=10)
        data = response.json()
        blacklisted = data.get('query_status') == 'ok' and data.get('blacklists', {}).get('spamhaus_dbl', 'not listed') != 'not listed'
        result = {'blacklisted': blacklisted, 'timestamp': int(time.time())}
        feed_cache[cache_key] = result
        return result
    except Exception as e:
        return {'blacklisted': False, 'timestamp': int(time.time()), 'error': str(e)}

def aggregate_feeds(url):
    """
    Aggregate results from ≥3 feeds with timestamps.
    Returns: {'feeds': list of dicts, 'overall_risk': float (0-1)}
    """
    feeds = [
        {'name': 'Google Safe Browsing', 'data': fetch_google_safe_browsing(url)},
        {'name': 'PhishTank', 'data': fetch_phishtank(url)},
        {'name': 'URLhaus', 'data': fetch_urlhaus(url)}
    ]
    # Additional feed: OpenPhish (if available, or simulate)
    try:
        response = requests.get('https://openphish.com/feed.txt', timeout=10)
        openphish_urls = set(response.text.splitlines())
        feeds.append({
            'name': 'OpenPhish',
            'data': {'phishing': url in openphish_urls, 'timestamp': int(time.time())}
        })
    except:
        feeds.append({
            'name': 'OpenPhish',
            'data': {'phishing': False, 'timestamp': int(time.time()), 'error': 'Unavailable'}
        })

    # Calculate overall risk: average of positive detections
    risks = []
    for feed in feeds:
        data = feed['data']
        if 'threat_type' in data and data['threat_type']:
            risks.append(1.0)
        elif data.get('phishing', False) or data.get('blacklisted', False):
            risks.append(1.0)
        else:
            risks.append(0.0)
    overall_risk = sum(risks) / len(risks) if risks else 0.0

    return {'feeds': feeds, 'overall_risk': overall_risk}
