from flask import Flask, render_template, request, jsonify
import numpy as np
import joblib
from urllib.parse import urlparse
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle
from utils import is_whitelisted

app = Flask(__name__)

try:
    url_model = joblib.load('url_model.joblib')
    url_vectorizer = joblib.load('url_vectorizer.joblib')
    print("URL model and vectorizer loaded successfully!")
except FileNotFoundError:
    print("Error: URL model files not found. Please run train_url_model.py first to train the model.")
    url_model, url_vectorizer = None, None

try:
    email_model = joblib.load('email_phishing_model.joblib')
    email_vectorizer = joblib.load('email_vectorizer.joblib')
    print("Email model loaded successfully!")
except FileNotFoundError:
    print("Error: Email model files not found. Please run email_trainer.py first to train the email model.")
    email_model, email_vectorizer = None, None

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
            
            # Vectorize URL content
            features = url_vectorizer.transform([url])
            
            # Hybrid Verification Step 1: Whitelist Check (Fastest & Most Reliable for Known Good)
            if is_whitelisted(url):
                 return jsonify({
                    'type': 'url',
                    'content': url,
                    'is_phishing': False,
                    'is_invalid': False,
                    'confidence': 100.0,
                    'prediction_text': 'Safe (Verified Official Domain)',
                    'risk_level': 'Low'
                })

            # REMOVED blocking DNS check. We now run the model first as per user request.
            # "Stick result to the output trained using kaggle dataset"

            # Vectorize URL content
            features = url_vectorizer.transform([url])
            
            # Prediction returns class label directly (e.g., 'bad', 'good')
            prediction = url_model.predict(features)[0]
            probability = url_model.predict_proba(features)[0]
            
            # Check for specific "bad" class label. Adjust if your dataset uses different labels (e.g., 'phishing', '1', etc.)
            # Based on 'phishing_site_urls.csv', labels are typically 'good' and 'bad'.
            is_phishing = (prediction == 'bad')
            
            confidence = float(max(probability) * 100)
            
            # Post-Prediction Logic
            is_invalid_url = False
            
            if is_phishing:
                # If model says Phishing, we trust it (Kaggle Dataset priority)
                prediction_text_override = 'Phishing'
            else:
                # If model says Safe, we trust it explicitly as per user request ("stick to kaggle dataset")
                # We NO LONGER check is_domain_active to override to "Invalid".
                # Historical "Good" URLs (even if dead now) must show as "Safe".
                prediction_text_override = 'Legitimate'
            
            # Logic: If Phishing (Bad) BUT confidence < 75% -> Override to "Safe" (BUT only if actually active)
            # User previously asked for this, but recently asked to "stick to kaggle output".
            # The "Retrain" improved confidence, so this override might trigger less often.
            # I will keep a light safety net: If Phishing is very low confidence, maybe question it?
            # But user said "stick to the output". I will DISABLE the <75% override for now to fully respect the model as requested.
            # "stick the result to the output trained using kaggle dataset" -> strict model adherence.
            
            # However, I should still handle the Yellow Box for Invalid URLs if they were "Safe".
            if is_invalid_url:
                 # Override everything if invalid
                 confidence = 0.0
                 is_phishing = False 
            
            # Match previous state without calibration
            result = {
                'type': 'url',
                'content': url,
                'is_phishing': is_phishing,
                'is_invalid': is_invalid_url,
                'confidence': round(confidence, 2),
                'prediction_text': prediction_text_override,
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
