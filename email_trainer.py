import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
import os
import requests
from email_features import extract_spambase_features

def download_spambase_if_needed():
    """Checks for spambase.data and downloads if missing (though it should be local as per user info)"""
    file_path = 'spambase.data'
    if os.path.exists(file_path):
        print(f"Found {file_path}")
        return True
    
    print("spambase.data not found locally. Attempting to download...")
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/spambase/spambase.data"
    try:
        response = requests.get(url)
        with open(file_path, 'wb') as f:
            f.write(response.content)
        print("Downloaded spambase.data")
        return True
    except Exception as e:
        print(f"Failed to download spambase.data: {e}")
        return False

def train_email_model():
    print("=== Email Phishing Detection Model Training (UCI Spambase) ===")
    
    if not download_spambase_if_needed():
        print("Cannot proceed without dataset.")
        return

    # Load dataset
    # The dataset has 57 features + 1 label (last column)
    try:
        data = pd.read_csv('spambase.data', header=None)
        print(f"Loaded dataset with shape: {data.shape}")
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return

    X = data.iloc[:, :-1]
    y = data.iloc[:, -1]
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {X_train.shape}")
    print(f"Testing set: {X_test.shape}")
    
    # Train Random Forest
    print("\nTraining Random Forest model...")
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        oob_score=True
    )
    rf_classifier.fit(X_train, y_train)
    print(f"OOB Score: {rf_classifier.oob_score_:.4f}")
    
    # Evaluate
    y_pred = rf_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Spam/Phishing']))
    
    # Save model
    model_filename = 'email_phishing_model.joblib'
    joblib.dump(rf_classifier, model_filename)
    print(f"Model saved to {model_filename}")
    
    # Note: We don't need to save a vectorizer because we are using a fixed feature extractor code.

    # Test with a few examples
    print("\n=== Testing with Sample Texts ===")
    examples = [
        "Urgent! You have won a lottery. Click here to claim your prize money now! 000000",
        "Refinance your home today! Free quote. Best interest rates available. Apply now.",
        "Hi Bob, just checking in on the project status. Let's meet tomorrow."
    ]
    
    for text in examples:
        features = extract_spambase_features(text)
        prediction = rf_classifier.predict(features)[0]
        prob = rf_classifier.predict_proba(features)[0]
        confidence = max(prob) * 100
        
        label = "Phishing/Spam" if prediction == 1 else "Legitimate"
        print(f"Text: '{text[:50]}...' -> {label} (Conf: {confidence:.2f}%)")

if __name__ == "__main__":
    train_email_model()

