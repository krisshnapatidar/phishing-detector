import re
import whois
import requests
import tldextract
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Feature Extraction Function
def extract_features(url):
    features = []
    
    # URL Length
    features.append(len(url))
    
    # Count of special characters
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('.'))
    
    # Check if HTTPS is present
    features.append(1 if "https" in url else 0)
    
    # Check if URL contains IP address
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # Domain-based features
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        domain_age = (datetime.now() - creation_date).days if creation_date else 0
        domain_expiry = (expiration_date - datetime.now()).days if expiration_date else 0
    except:
        domain_age = 0
        domain_expiry = 0
    
    features.append(domain_age)
    features.append(domain_expiry)
    
    return features

# Dummy dataset
phishing_data = pd.DataFrame({
    'url': ['http://example.com', 'http://phishingsite.com', 'https://securebank.com', 'http://malicious.com'],
    'label': [0, 1, 0, 1]  # 0 = Safe, 1 = Phishing
})

# Extract features for each URL
X = np.array([extract_features(url) for url in phishing_data['url']])
y = phishing_data['label'].values

# Train Model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f'Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%')

# Prediction Function
def predict_phishing(url):
    features = np.array(extract_features(url)).reshape(1, -1)
    prediction = model.predict(features)
    return "Phishing" if prediction[0] == 1 else "Safe"

# Example Usage
print(predict_phishing("http://suspicious-link.com"))
