import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import time
from database import query_db, insert_db
from celery import Celery
from config import get_config
import logging
import redis

config = get_config()
celery = Celery('active_learning', broker=config.REDIS_URL)
r = redis.Redis.from_url(config.REDIS_URL) if config.REDIS_URL else None
logging.basicConfig(level=logging.INFO)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishguard_model.pkl')

@celery.task
def retrain_model_async():
    """
    Async task to retrain model with new feedback data.
    """
    try:
        X, y = load_feedback_data()
        if len(X) < 10:  # Minimum data for retraining
            logging.info("Not enough feedback data for retraining.")
            return

        # Load existing model
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            model = RandomForestClassifier(n_estimators=100, random_state=42)

        # Retrain with new data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)

        # Save updated model
        joblib.dump(model, MODEL_PATH)

        # Log retraining
        insert_db('INSERT INTO model_versions (version, accuracy, report) VALUES (?, ?, ?)',
                  (f"retrained_{int(time.time())}", accuracy, json.dumps(report)))

        # Cache model metadata in Redis
        if r:
            r.setex('model_accuracy', 3600, accuracy)
            r.setex('model_report', 3600, json.dumps(report))

        logging.info(f"Model retrained with accuracy: {accuracy:.2f}")
    except Exception as e:
        logging.error(f"Retraining failed: {str(e)}")

def load_feedback_data():
    """
    Load labeled feedback from DB for retraining with Redis caching.
    Returns: X (features), y (labels)
    """
    cache_key = 'feedback_data'
    if r:
        cached = r.get(cache_key)
        if cached:
            data = json.loads(cached)
            return np.array(data['X']), np.array(data['y'])

    feedback = query_db('SELECT url, user_label FROM feedback')
    X = []
    y = []
    for item in feedback:
        # Extract features from URL (reuse backend logic)
        from backend import extract_features  # Import here to avoid circular
        features = extract_features(item['url'])
        if features:
            # Convert to vector (match create_model.py order)
            vector = [
                features['urlLength'], features['domainLength'], features['pathLength'],
                features['specialChars'], features['digits'], features['letters'],
                features['subdomainCount'], features['domainTokens'], features['hostnameEntropy'],
                features['isHttps'], features['hasPort'], features['portNumber'],
                features['suspiciousKeywords'], features['hasIP'], features['hasPrivateIP'],
                features['isShortened'], features['pathDepth'], features['hasQueryParams'],
                features['queryParamsCount'], features['hasRedirect'], features['hasLogin'],
                features['hasSecure'], features['hasHex'], features['suspiciousTLD'],
                features['domainAge'], features['hasPunycode'], features['hasLoginForm'],
                features['alexa_rank']
            ]
            X.append(vector)
            y.append(1 if item['user_label'] == 'phishing' else 0)

    data = {'X': X, 'y': y}
    if r:
        r.setex(cache_key, 1800, json.dumps(data))  # Cache for 30 minutes

    return np.array(X), np.array(y)

def submit_feedback(url, user_label, user_id):
    """
    Submit user feedback for active learning.
    """
    insert_db('INSERT INTO feedback (url, user_label, user_id) VALUES (?, ?, ?)',
              (url, user_label, user_id))
    # Invalidate cache
    if r:
        r.delete('feedback_data')
    # Trigger async retraining
    retrain_model_async.delay()

def get_model_stats():
    """
    Get cached model statistics.
    """
    if r:
        accuracy = r.get('model_accuracy')
        report = r.get('model_report')
        if accuracy and report:
            return {'accuracy': float(accuracy), 'report': json.loads(report)}
    # Fallback to DB
    versions = query_db('SELECT accuracy, report FROM model_versions ORDER BY timestamp DESC LIMIT 1')
    if versions:
        return {'accuracy': versions[0]['accuracy'], 'report': json.loads(versions[0]['report'])}
    return None

if __name__ == '__main__':
    # For testing
    retrain_model_async()
