from flask import Flask, render_template, request, jsonify
import numpy as np
import joblib
from urllib.parse import urlparse
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle

app = Flask(__name__)

try:
    url_model = joblib.load('phishing_detector_model.joblib')
    print("URL model loaded successfully!")
except FileNotFoundError:
    print("Error: URL model file not found. Please run main.py first to train the model.")
    url_model = None

try:
    email_model = joblib.load('email_phishing_model.joblib')
    email_vectorizer = joblib.load('email_vectorizer.joblib')
    print("Email model loaded successfully!")
except FileNotFoundError:
    print("Error: Email model files not found. Please run email_trainer.py first to train the email model.")
    email_model, email_vectorizer = None, None

def extract_features_from_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path
    except:
        return np.full(30, -1)

    features = np.full(30, -1)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        features[0] = 1
    else:
        features[0] = -1
    if len(url) >= 75:
        features[1] = 1
    elif len(url) < 54:
        features[1] = -1
    else:
        features[1] = 0
    shortening_services = ['bit.ly', 't.co', 'goo.gl', 'tinyurl', 'short.ly', 'ow.ly', 'is.gd']
    if any(service in hostname for service in shortening_services):
        features[2] = 1
    else:
        features[2] = -1
    

    features[3] = 1 if '@' in url else -1
    features[4] = 1 if url.rfind('//') > 7 else -1
    features[5] = 1 if '-' in hostname else -1
    subdomain_count = hostname.count('.') - 1
    features[6] = 1 if subdomain_count > 2 else -1
    features[7] = 1 if parsed_url.scheme == 'https' else -1
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    features[8] = 1 if len(tld) > 4 else -1
    features[9] = -1
    port = parsed_url.port
    if port and port not in [80, 443, 8080]:
        features[10] = 1
    else:
        features[10] = -1
    features[11] = 1 if 'https' in hostname else -1
    features[12] = -1
    features[13] = -1
    features[14] = -1
    features[15] = -1
    features[16] = -1
    suspicious_patterns = ['login', 'verify', 'account', 'update', 'secure', 'bank']
    features[17] = 1 if any(pattern in url.lower() for pattern in suspicious_patterns) else -1
    features[18] = -1
    features[19] = -1
    features[20] = -1
    features[21] = -1
    features[22] = -1
    features[23] = -1
    features[24] = -1
    features[25] = -1
    features[26] = -1
    features[27] = -1
    features[28] = -1
    features[29] = -1
    return features

def analyze_email_content(email_text):
    if email_model is None or email_vectorizer is None:
        return None
    email_features = email_vectorizer.transform([email_text])
    prediction = email_model.predict(email_features)[0]
    probability = email_model.predict_proba(email_features)[0]
    is_phishing = bool(prediction == 1)
    confidence = float(max(probability) * 100)
    return {
        'is_phishing': is_phishing,
        'confidence': round(confidence, 2),
        'prediction_text': 'Phishing' if is_phishing else 'Legitimate',
        'risk_level': 'High' if confidence > 80 else 'Medium' if confidence > 60 else 'Low'
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        analysis_type = data.get('type', 'url')
        if analysis_type == 'url':
            if url_model is None:
                return jsonify({'error': 'URL model not loaded. Please train the model first.'})
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'error': 'Please provide a URL'})
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            features = extract_features_from_url(url)
            features_reshaped = features.reshape(1, -1)
            prediction = url_model.predict(features_reshaped)[0]
            probability = url_model.predict_proba(features_reshaped)[0]
            is_phishing = bool(prediction == 1)
            confidence = float(max(probability) * 100)
            result = {
                'type': 'url',
                'content': url,
                'is_phishing': is_phishing,
                'confidence': round(confidence, 2),
                'prediction_text': 'Phishing' if is_phishing else 'Legitimate',
                'risk_level': 'High' if confidence > 80 else 'Medium' if confidence > 60 else 'Low'
            }
        elif analysis_type == 'email':
            if email_model is None:
                return jsonify({'error': 'Email model not loaded.'})
            email_text = data.get('email', '').strip()
            if not email_text:
                return jsonify({'error': 'Please provide email content'})
            email_result = analyze_email_content(email_text)
            if email_result is None:
                return jsonify({'error': 'Error analyzing email content'})
            result = {
                'type': 'email',
                'content': email_text[:100] + '...' if len(email_text) > 100 else email_text,
                'is_phishing': email_result['is_phishing'],
                'confidence': email_result['confidence'],
                'prediction_text': email_result['prediction_text'],
                'risk_level': email_result['risk_level']
            }
        else:
            return jsonify({'error': 'Invalid analysis type. Use "url" or "email".'})
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Error processing request: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
