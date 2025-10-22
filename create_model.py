import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

# Generate realistic synthetic training data based on actual features
np.random.seed(42)
n_samples = 10000
n_features = 23  # Based on the feature extraction in backend.py

# Feature names for reference (matching backend):
# 0: urlLength, 1: domainLength, 2: pathLength, 3: specialChars, 4: digits, 5: letters,
# 6: subdomainCount, 7: domainTokens, 8: hostnameEntropy, 9: isHttps, 10: hasPort,
# 11: portNumber, 12: suspiciousKeywords, 13: hasIP, 14: hasPrivateIP, 15: isShortened,
# 16: pathDepth, 17: hasQueryParams, 18: queryParamsCount, 19: hasRedirect,
# 20: hasLogin, 21: hasSecure, 22: hasHex, 23: suspiciousTLD, 24: domainAge,
# 25: hasPunycode, 26: hasLoginForm, 27: alexa_rank

X = np.zeros((n_samples, n_features))
y = np.zeros(n_samples, dtype=int)

for i in range(n_samples):
    is_phishing = np.random.rand() < 0.3  # 30% phishing samples
    y[i] = int(is_phishing)

    if is_phishing:
        # Phishing URL characteristics
        X[i, 0] = np.random.uniform(50, 200)  # longer URLs
        X[i, 1] = np.random.uniform(10, 50)   # longer domains
        X[i, 2] = np.random.uniform(10, 100)  # longer paths
        X[i, 3] = np.random.uniform(5, 30)    # more special chars
        X[i, 4] = np.random.uniform(5, 20)    # more digits
        X[i, 5] = np.random.uniform(20, 100)  # letters
        X[i, 6] = np.random.uniform(2, 5)     # more subdomains
        X[i, 7] = np.random.uniform(3, 6)     # more domain tokens
        X[i, 8] = np.random.uniform(4.0, 5.5) # higher entropy
        X[i, 9] = np.random.choice([0, 1], p=[0.7, 0.3])  # less HTTPS
        X[i, 10] = np.random.choice([0, 1], p=[0.8, 0.2])  # some have ports
        X[i, 11] = np.random.choice([80, 443, 8080, 8443], p=[0.4, 0.4, 0.1, 0.1])
        X[i, 12] = np.random.uniform(2, 8)    # more suspicious keywords
        X[i, 13] = np.random.choice([0, 1], p=[0.6, 0.4])  # some use IP
        X[i, 14] = np.random.choice([0, 1], p=[0.9, 0.1])  # few private IPs
        X[i, 15] = np.random.choice([0, 1], p=[0.5, 0.5])  # shortened URLs
        X[i, 16] = np.random.uniform(2, 6)    # deeper paths
        X[i, 17] = np.random.choice([0, 1], p=[0.3, 0.7])  # more query params
        X[i, 18] = np.random.uniform(2, 10)   # more query params count
        X[i, 19] = np.random.choice([0, 1], p=[0.4, 0.6])  # redirects
        X[i, 20] = np.random.choice([0, 1], p=[0.5, 0.5])  # login paths
        X[i, 21] = np.random.choice([0, 1], p=[0.6, 0.4])  # secure paths
        X[i, 22] = np.random.choice([0, 1], p=[0.7, 0.3])  # hex encoding
    else:
        # Benign URL characteristics
        X[i, 0] = np.random.uniform(20, 80)   # shorter URLs
        X[i, 1] = np.random.uniform(5, 20)    # shorter domains
        X[i, 2] = np.random.uniform(0, 20)    # shorter paths
        X[i, 3] = np.random.uniform(0, 10)    # fewer special chars
        X[i, 4] = np.random.uniform(0, 5)     # fewer digits
        X[i, 5] = np.random.uniform(10, 50)   # letters
        X[i, 6] = np.random.uniform(0, 2)     # fewer subdomains
        X[i, 7] = np.random.uniform(2, 4)     # fewer domain tokens
        X[i, 8] = np.random.uniform(3.0, 4.5) # lower entropy
        X[i, 9] = np.random.choice([0, 1], p=[0.1, 0.9])  # mostly HTTPS
        X[i, 10] = np.random.choice([0, 1], p=[0.95, 0.05])  # few ports
        X[i, 11] = np.random.choice([80, 443], p=[0.1, 0.9])
        X[i, 12] = np.random.uniform(0, 2)    # fewer suspicious keywords
        X[i, 13] = 0  # no IPs
        X[i, 14] = 0  # no private IPs
        X[i, 15] = np.random.choice([0, 1], p=[0.9, 0.1])  # few shortened
        X[i, 16] = np.random.uniform(0, 3)    # shallower paths
        X[i, 17] = np.random.choice([0, 1], p=[0.6, 0.4])  # fewer query params
        X[i, 18] = np.random.uniform(0, 3)    # fewer query params count
        X[i, 19] = np.random.choice([0, 1], p=[0.8, 0.2])  # fewer redirects
        X[i, 20] = np.random.choice([0, 1], p=[0.9, 0.1])  # few login paths
        X[i, 21] = np.random.choice([0, 1], p=[0.8, 0.2])  # fewer secure paths
        X[i, 22] = np.random.choice([0, 1], p=[0.95, 0.05])  # rare hex

# Add remaining features (suspiciousTLD, domainAge, hasPunycode, hasLoginForm, alexa_rank)
for i in range(n_samples):
    if y[i] == 1:  # phishing
        X[i, 23] = np.random.choice([0, 1], p=[0.3, 0.7])  # suspicious TLD
        X[i, 24] = np.random.uniform(0, 30)   # young domains
        X[i, 25] = np.random.choice([0, 1], p=[0.8, 0.2])  # punycode
        X[i, 26] = np.random.choice([0, 1], p=[0.4, 0.6])  # login forms
        X[i, 27] = np.random.uniform(100000, 1000000)  # low alexa rank
    else:  # benign
        X[i, 23] = np.random.choice([0, 1], p=[0.9, 0.1])  # few suspicious TLD
        X[i, 24] = np.random.uniform(365, 3650)  # older domains
        X[i, 25] = np.random.choice([0, 1], p=[0.95, 0.05])  # rare punycode
        X[i, 26] = np.random.choice([0, 1], p=[0.8, 0.2])  # fewer login forms
        X[i, 27] = np.random.uniform(1, 100000)  # high alexa rank

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train RandomForest model
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Model Accuracy: {accuracy:.4f}')
print('\nClassification Report:')
print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))

# Save the model
joblib.dump(model, 'phishguard_model.pkl')
print('\nImproved ML model saved as phishguard_model.pkl')
