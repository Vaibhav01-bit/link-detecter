import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os
from database import query_db
import subprocess

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishguard_model.pkl')

def load_feedback_data():
    """
    Load labeled feedback from DB for retraining.
    Returns: X (features), y (labels)
    """
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
    return np.array(X), np.array(y)

def retrain_model():
    """
    Retrain model with feedback data + synthetic data.
    Queued via subprocess or Celery.
    """
    # Load existing synthetic data (simulate from create_model.py)
    # For simplicity, regenerate synthetic + append feedback
    np.random.seed(42)
    n_samples = 5000  # Smaller for quick retrain
    n_features = 28
    X_synth = np.zeros((n_samples, n_features))
    y_synth = np.zeros(n_samples, dtype=int)

    for i in range(n_samples):
        is_phishing = np.random.rand() < 0.3
        y_synth[i] = int(is_phishing)
        # Simplified synthetic generation (match create_model.py logic)
        if is_phishing:
            X_synth[i, 0] = np.random.uniform(50, 200)
            X_synth[i, 1] = np.random.uniform(10, 50)
            X_synth[i, 8] = np.random.uniform(4.0, 5.5)
            X_synth[i, 9] = 0  # Less HTTPS
            X_synth[i, 12] = np.random.uniform(2, 8)
            X_synth[i, 15] = 1  # Shortened
            X_synth[i, 24] = np.random.uniform(0, 30)
        else:
            X_synth[i, 0] = np.random.uniform(20, 80)
            X_synth[i, 1] = np.random.uniform(5, 20)
            X_synth[i, 8] = np.random.uniform(3.0, 4.5)
            X_synth[i, 9] = 1  # Mostly HTTPS
            X_synth[i, 24] = np.random.uniform(365, 3650)

    # Load feedback
    X_fb, y_fb = load_feedback_data()
    if len(X_fb) > 0:
        X_combined = np.vstack([X_synth, X_fb])
        y_combined = np.hstack([y_synth, y_fb])
    else:
        X_combined, y_combined = X_synth, y_synth

    # Retrain
    X_train, X_test, y_train, y_test = train_test_split(X_combined, y_combined, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f'Retrained Model Accuracy: {accuracy:.4f}')

    # Save
    joblib.dump(model, MODEL_PATH)
    print('Model retrained and saved.')

def queue_retrain():
    """
    Queue retraining job (simple subprocess for now; use Celery in production).
    """
    subprocess.Popen(['python', 'active_learning.py', 'retrain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'retrain':
        retrain_model()
