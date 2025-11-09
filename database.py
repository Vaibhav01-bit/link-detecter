import sqlite3
from flask import g
import os
import redis
from config import get_config
import logging
import json

config = get_config()
r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None
logging.basicConfig(level=logging.INFO)

DATABASE = os.path.join(os.path.dirname(__file__), 'phishguard.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db(app):
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Scans table: store scan results with user, cluster, feedback
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                phishing BOOLEAN NOT NULL,
                score REAL NOT NULL,
                confidence REAL NOT NULL,
                reason_codes TEXT,  -- JSON string
                features TEXT,      -- JSON string
                model TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                cluster_id INTEGER,
                feedback_label TEXT,  -- 'phishing', 'safe', or NULL
                feeds_data TEXT,     -- JSON string of feed results
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (cluster_id) REFERENCES clusters (id)
            )
        ''')
        # Users table: for auth and roles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'auditor',  -- 'admin' or 'auditor'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Feedback table: for active learning
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                user_label TEXT NOT NULL,  -- 'phishing' or 'safe'
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Clusters table: for similarity clustering
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                summary TEXT NOT NULL,  -- e.g., "Campaign X: 5 similar login pages"
                pages TEXT NOT NULL,    -- JSON list of URLs
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Alerts table: for enterprise alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule TEXT NOT NULL,     -- e.g., 'score > 0.7'
                message TEXT NOT NULL,
                triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Metrics table: for false positives tracking and A/B testing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                variant TEXT,  -- e.g., 'old_model' or 'new_model' for A/B
                prediction INTEGER NOT NULL,  -- 0 safe, 1 phishing
                actual INTEGER,  -- from feedback, 0 or 1 or NULL
                false_positive BOOLEAN DEFAULT FALSE,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')

        # Model versions table: for tracking model retraining
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                accuracy REAL NOT NULL,
                report TEXT,  -- JSON string
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        db.commit()

def close_db(e=None):
    db = g.pop('_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(query, args)
    db.commit()
    return cur.lastrowid

def cache_scan_result(url, result, ttl=3600):
    """
    Cache scan result in Redis for faster lookups.
    """
    if r:
        key = f'scan_{hash(url)}'
        r.setex(key, ttl, json.dumps(result))

def get_cached_scan(url):
    """
    Retrieve cached scan result.
    """
    if r:
        key = f'scan_{hash(url)}'
        cached = r.get(key)
        if cached:
            return json.loads(cached)
    return None
