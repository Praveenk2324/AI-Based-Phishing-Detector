import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
from urllib.parse import urlparse
import re
from ucimlrepo import fetch_ucirepo

data = fetch_ucirepo(id=327)

X = data.data.features
y = data.data.targets.values.ravel()  

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("\nData split into training and testing sets:")
print("Training set size:", X_train.shape[0])
print("Testing set size:", X_test.shape[0])

print("\nTraining the Random Forest model...")

rf_classifier = RandomForestClassifier(n_estimators=100, max_features='sqrt', oob_score=True, random_state=42)
rf_classifier.fit(X_train, y_train)

print("Model training completed.")
print(f"Out-of-Bag Score: {rf_classifier.oob_score_:.4f}")

print("\nEvaluating the model on the test set...")

y_pred = rf_classifier.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate (-1)', 'Phishing (1)']))

model_filename = 'phishing_detector_model.joblib'
joblib.dump(rf_classifier, model_filename)
print(f"\nTrained model saved to '{model_filename}'")


def extract_features_from_url(url):
    """
    Extract features from URL to match the UCI phishing dataset format.
    Returns a numpy array with 30 features matching the dataset columns.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path
    except:
        # Return array of -1 if URL parsing fails (indicating suspicious)
        return np.full(30, -1)

    # Initialize features array with -1 (suspicious by default)
    features = np.full(30, -1)
    
    # 1. having_ip_address: 1 if IP address, -1 if domain name
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        features[0] = 1
    else:
        features[0] = -1
    
    # 2. url_length: 1 if >= 75, -1 if < 54, 0 otherwise
    if len(url) >= 75:
        features[1] = 1
    elif len(url) < 54:
        features[1] = -1
    else:
        features[1] = 0
    
    # 3. shortining_service: 1 if shortening service, -1 if not
    shortening_services = ['bit.ly', 't.co', 'goo.gl', 'tinyurl', 'short.ly', 'ow.ly', 'is.gd']
    if any(service in hostname for service in shortening_services):
        features[2] = 1
    else:
        features[2] = -1
    
    # 4. having_at_symbol: 1 if @ in URL, -1 if not
    features[3] = 1 if '@' in url else -1
    
    # 5. double_slash_redirecting: 1 if // after protocol, -1 if not
    features[4] = 1 if url.rfind('//') > 7 else -1
    
    # 6. prefix_suffix: 1 if - in hostname, -1 if not
    features[5] = 1 if '-' in hostname else -1
    
    # 7. having_sub_domain: 1 if subdomain count > 2, -1 if not
    subdomain_count = hostname.count('.') - 1
    features[6] = 1 if subdomain_count > 2 else -1
    
    # 8. sslfinal_state: 1 if https, -1 if http
    features[7] = 1 if parsed_url.scheme == 'https' else -1
    
    # 9. domain_registration_length: 1 if TLD length > 4, -1 if not
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    features[8] = 1 if len(tld) > 4 else -1
    
    # 10. favicon: -1 (cannot determine from URL alone)
    features[9] = -1
    
    # 11. port: 1 if non-standard port, -1 if standard
    port = parsed_url.port
    if port and port not in [80, 443, 8080]:
        features[10] = 1
    else:
        features[10] = -1
    
    # 12. https_token: 1 if https in domain, -1 if not
    features[11] = 1 if 'https' in hostname else -1
    
    # 13. request_url: -1 (cannot determine from URL alone)
    features[12] = -1
    
    # 14. url_of_anchor: -1 (cannot determine from URL alone)
    features[13] = -1
    
    # 15. links_in_tags: -1 (cannot determine from URL alone)
    features[14] = -1
    
    # 16. sfh: -1 (cannot determine from URL alone)
    features[15] = -1
    
    # 17. submitting_to_email: -1 (cannot determine from URL alone)
    features[16] = -1
    
    # 18. abnormal_url: 1 if suspicious patterns, -1 if normal
    suspicious_patterns = ['login', 'verify', 'account', 'update', 'secure', 'bank']
    features[17] = 1 if any(pattern in url.lower() for pattern in suspicious_patterns) else -1
    
    # 19. redirect: -1 (cannot determine from URL alone)
    features[18] = -1
    
    # 20. on_mouseover: -1 (cannot determine from URL alone)
    features[19] = -1
    
    # 21. rightclick: -1 (cannot determine from URL alone)
    features[20] = -1
    
    # 22. popupwindow: -1 (cannot determine from URL alone)
    features[21] = -1
    
    # 23. iframe: -1 (cannot determine from URL alone)
    features[22] = -1
    
    # 24. age_of_domain: -1 (cannot determine from URL alone)
    features[23] = -1
    
    # 25. dnsrecord: -1 (cannot determine from URL alone)
    features[24] = -1
    
    # 26. web_traffic: -1 (cannot determine from URL alone)
    features[25] = -1
    
    # 27. page_rank: -1 (cannot determine from URL alone)
    features[26] = -1
    
    # 28. google_index: -1 (cannot determine from URL alone)
    features[27] = -1
    
    # 29. links_pointing_to_page: -1 (cannot determine from URL alone)
    features[28] = -1
    
    # 30. statistical_report: -1 (cannot determine from URL alone)
    features[29] = -1
    
    return features


print("\n--- Testing with a new URL ---")
loaded_model = joblib.load(model_filename)
print("Model loaded successfully.")

safe_url = "https://www.google.com"
suspicious_url = "http://verify-account-update.com/login"
phishing_url_ip = "http://182.121.11.23/some-path"
phishing_url_suspicious = "http://bit.ly/suspicious-link"
phishing_url_at = "http://user@malicious-site.com"

safe_features = extract_features_from_url(safe_url).reshape(1, -1)
suspicious_features = extract_features_from_url(suspicious_url).reshape(1, -1)
phishing_features = extract_features_from_url(phishing_url_ip).reshape(1, -1)
phishing_features_suspicious = extract_features_from_url(phishing_url_suspicious).reshape(1, -1)
phishing_features_at = extract_features_from_url(phishing_url_at).reshape(1, -1)

prediction_safe = loaded_model.predict(safe_features)
prediction_suspicious = loaded_model.predict(suspicious_features)
prediction_phishing = loaded_model.predict(phishing_features)
prediction_phishing_suspicious = loaded_model.predict(phishing_features_suspicious)
prediction_phishing_at = loaded_model.predict(phishing_features_at)


def print_prediction(url, prediction):
    result = "Phishing (1)" if prediction[0] == 1 else "Legitimate (-1)"
    print(f"The URL '{url}' is predicted as: {result}")


print_prediction(safe_url, prediction_safe)
print_prediction(suspicious_url, prediction_suspicious)
print_prediction(phishing_url_ip, prediction_phishing)
print_prediction(phishing_url_suspicious, prediction_phishing_suspicious)
print_prediction(phishing_url_at, prediction_phishing_at)
