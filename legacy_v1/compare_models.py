import joblib
import pandas as pd
import numpy as np
from utils import extract_features_from_url
from sklearn.feature_extraction.text import TfidfVectorizer

def compare_models():
    print("Loading models...")
    
    # Load Original Model
    try:
        original_model = joblib.load('phishing_detector_model.joblib')
        print("Original Model loaded.")
    except Exception as e:
        print(f"Error loading Original Model: {e}")
        return

    # Load Kaggle Model
    try:
        kaggle_model = joblib.load('kaggle_phishing_model.joblib')
        kaggle_vectorizer = joblib.load('kaggle_vectorizer.joblib')
        print("Kaggle Model loaded.")
    except Exception as e:
        print(f"Error loading Kaggle Model: {e}")
        return

    # Test URLs
    test_urls = [
        # Safe
        "https://www.google.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://en.wikipedia.org/wiki/Main_Page",
        
        # Phishing / Suspicious (Obvious)
        "http://secure-login-apple.com",
        "http://paypal-verification.net",
        "http://update-your-account-now.com/login",
        
        # User's tricky example (Non-resolving / Complex)
        "www.dghjdgf.com/paypal.co.uk/cycgi-bin/webscrcmd=_home-customer&nav=1/loading.php",
        
        # Other tricky patterns
        "http://192.168.1.1/admin",
        "http://bit.ly/suspicious-link"
    ]

    with open('comparison_results.txt', 'w', encoding='utf-8') as f:
        f.write("\n" + "="*80 + "\n")
        f.write(f"{'URL':<50} | {'Original':<12} | {'Kaggle':<12}\n")
        f.write("="*80 + "\n")

        for url in test_urls:
            # Original Model Prediction
            try:
                url_for_original = url
                if not url_for_original.startswith(('http://', 'https://')):
                    url_for_original = 'http://' + url_for_original
                    
                features = extract_features_from_url(url_for_original)
                pred_orig_raw = original_model.predict(features.reshape(1, -1))[0]
                res_orig = "Phishing" if pred_orig_raw == 1 else "Safe"
            except Exception as e:
                res_orig = "Error"

            # Kaggle Model Prediction
            try:
                features_kaggle = kaggle_vectorizer.transform([url])
                pred_kaggle = kaggle_model.predict(features_kaggle)[0]
                res_kaggle = str(pred_kaggle)
            except Exception as e:
                res_kaggle = "Error"

            f.write(f"{url[:47]+'...' if len(url)>47 else url:<50} | {res_orig:<12} | {res_kaggle:<12}\n")

        f.write("="*80 + "\n")
    
    print("Comparison results saved to comparison_results.txt")

if __name__ == "__main__":
    compare_models()
