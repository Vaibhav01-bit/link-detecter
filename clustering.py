import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
import json
from database import query_db, insert_db

def vectorize_features(features):
    """
    Convert feature dict to vector for clustering.
    Focus on similarity: hostname, path, keywords, entropy.
    """
    vector = [
        features.get('hostnameEntropy', 0),
        features.get('suspiciousKeywords', 0),
        features.get('urlLength', 0),
        features.get('subdomainCount', 0),
        features.get('hasIP', 0),
        features.get('isShortened', 0),
        features.get('hasHex', 0),
        features.get('domainAge', 365) / 3650  # Normalize
    ]
    return np.array(vector)

def cluster_similar_scans(limit=100):
    """
    Run DBSCAN clustering on recent scans.
    Group similar phishing attempts into campaigns.
    Returns: list of cluster summaries
    """
    # Fetch recent scans
    scans = query_db('SELECT id, url, features FROM scans WHERE phishing = 1 ORDER BY timestamp DESC LIMIT ?', (limit,))
    if len(scans) < 5:  # Need minimum for clustering
        return []

    vectors = []
    urls = []
    for scan in scans:
        features = json.loads(scan['features'])
        vector = vectorize_features(features)
        vectors.append(vector)
        urls.append(scan['url'])

    vectors = np.array(vectors)
    # Normalize vectors
    vectors = (vectors - vectors.mean(axis=0)) / (vectors.std(axis=0) + 1e-8)

    # DBSCAN: eps=0.5 (similarity threshold), min_samples=2
    clustering = DBSCAN(eps=0.5, min_samples=2, metric='euclidean').fit(vectors)
    labels = clustering.labels_

    clusters = {}
    for i, label in enumerate(labels):
        if label == -1:  # Noise
            continue
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(urls[i])

    summaries = []
    for label, cluster_urls in clusters.items():
        if len(cluster_urls) >= 2:
            # Generate summary: e.g., "Campaign X: 5 similar login pages on new domains"
            summary = f"Campaign {label + 1}: {len(cluster_urls)} similar pages"
            # Insert into DB
            cluster_id = insert_db('INSERT INTO clusters (summary, pages) VALUES (?, ?)',
                                   (summary, json.dumps(cluster_urls)))
            summaries.append({'id': cluster_id, 'summary': summary, 'pages': cluster_urls})

    return summaries

def assign_cluster_to_scan(url, features):
    """
    Assign cluster to a new scan if it matches existing clusters.
    Returns: cluster_id or None
    """
    clusters = query_db('SELECT id, pages FROM clusters')
    scan_vector = vectorize_features(features)
    scan_vector = (scan_vector - scan_vector.mean()) / (scan_vector.std() + 1e-8)

    for cluster in clusters:
        pages = json.loads(cluster['pages'])
        # Simple check: if URL hostname matches any in cluster
        scan_hostname = url.split('/')[2] if '//' in url else url
        cluster_hostnames = [p.split('/')[2] if '//' in p else p for p in pages]
        if scan_hostname in cluster_hostnames:
            return cluster['id']

    return None
