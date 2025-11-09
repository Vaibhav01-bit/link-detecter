import numpy as np
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
import json
from database import query_db, insert_db
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from celery import Celery
from config import get_config
import redis
import logging

config = get_config()
celery = Celery('clustering', broker=config.REDIS_URL)
r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None
logging.basicConfig(level=logging.INFO)

@celery.task
def cluster_similar_scans_async(limit=100):
    """
    Async DBSCAN clustering on recent scans.
    Group similar phishing attempts into campaigns.
    Returns: list of cluster summaries
    """
    try:
        # Fetch recent scans
        scans = query_db('SELECT id, url, features FROM scans WHERE phishing = 1 ORDER BY timestamp DESC LIMIT ?', (limit,))
        if len(scans) < 5:  # Need minimum for clustering
            logging.info("Not enough scans for clustering.")
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
                # Enhanced summary: analyze common patterns
                common_domain = analyze_common_patterns(cluster_urls)
                summary = f"Campaign {label + 1}: {len(cluster_urls)} similar pages - {common_domain}"
                # Insert into DB
                cluster_id = insert_db('INSERT INTO clusters (summary, pages) VALUES (?, ?)',
                                       (summary, json.dumps(cluster_urls)))
                summaries.append({'id': cluster_id, 'summary': summary, 'pages': cluster_urls})

        # Cache clusters in Redis
        if r:
            r.setex('clusters', 3600, json.dumps(summaries))

        logging.info(f"Clustered {len(summaries)} campaigns.")
        return summaries
    except Exception as e:
        logging.error(f"Clustering failed: {str(e)}")
        return []

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
        features.get('domainAge', 365) / 3650,  # Normalize
        features.get('hasPunycode', 0),
        features.get('hasLoginForm', 0)
    ]
    return np.array(vector)

def analyze_common_patterns(urls):
    """
    Analyze common patterns in cluster URLs.
    Returns: string describing common theme.
    """
    domains = [urlparse(url).netloc for url in urls]
    paths = [urlparse(url).path for url in urls]
    common_domain = max(set(domains), key=domains.count) if domains else 'unknown'
    common_path = max(set(paths), key=paths.count) if paths else '/'
    return f"Common domain: {common_domain}, path: {common_path}"

def assign_cluster_to_scan(url, features):
    """
    Assign cluster to a new scan if it matches existing clusters.
    Returns: cluster_id or None
    """
    try:
        # Check Redis cache first
        cached_clusters = None
        if r:
            try:
                cached_clusters = r.get('clusters')
            except Exception as cache_error:
                logging.warning(f"Redis cache error for clusters: {cache_error}")
                cached_clusters = None
                
        clusters = []
        if cached_clusters:
            clusters = json.loads(cached_clusters)
        else:
            db_clusters = query_db('SELECT id, pages FROM clusters')
            if db_clusters:
                clusters = db_clusters

        # If there are no clusters yet, return None
        if not clusters:
            return None

        scan_hostname = urlparse(url).netloc

        for cluster in clusters:
            try:
                # Handle different possible data formats
                if isinstance(cluster, dict):
                    pages = cluster.get('pages', [])
                    cluster_id = cluster.get('id')
                else:
                    pages = []
                    cluster_id = None
                    
                if isinstance(pages, str):
                    pages = json.loads(pages)
                elif not isinstance(pages, list):
                    continue
                    
                cluster_hostnames = [urlparse(p).netloc for p in pages]
                if scan_hostname in cluster_hostnames:
                    return cluster_id
            except Exception as e:
                logging.warning(f"Error processing cluster: {str(e)}")
                continue

        return None
    except Exception as e:
        logging.error(f"Error in assign_cluster_to_scan: {str(e)}")
        return None

def visualize_clusters(limit=100):
    """
    Generate 2D visualization of clusters using PCA.
    Returns: Matplotlib figure.
    """
    scans = query_db('SELECT id, url, features FROM scans WHERE phishing = 1 ORDER BY timestamp DESC LIMIT ?', (limit,))
    if len(scans) < 5:
        return None

    vectors = []
    labels = []
    for scan in scans:
        features = json.loads(scan['features'])
        vector = vectorize_features(features)
        vectors.append(vector)
        # Assign label from existing clusters or -1
        cluster_id = assign_cluster_to_scan(scan['url'], features)
        labels.append(cluster_id if cluster_id else -1)

    vectors = np.array(vectors)
    vectors = (vectors - vectors.mean(axis=0)) / (vectors.std(axis=0) + 1e-8)

    pca = PCA(n_components=2)
    reduced = pca.fit_transform(vectors)

    fig, ax = plt.subplots()
    unique_labels = set(labels)
    colors = plt.cm.Spectral(np.linspace(0, 1, len(unique_labels)))
    for k, col in zip(unique_labels, colors):
        class_member_mask = (np.array(labels) == k)
        xy = reduced[class_member_mask]
        ax.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=col, markeredgecolor='k', markersize=6, label=f'Cluster {k}' if k != -1 else 'Noise')
    ax.set_title('Phishing Clusters Visualization')
    ax.legend()
    return fig
