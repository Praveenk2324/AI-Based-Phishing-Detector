import pandas as pd
import numpy as np
import joblib
import time
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from urllib.parse import urlparse
import re
from ucimlrepo import fetch_ucirepo

def train_and_evaluate_model(name, model, params, X_train, y_train, X_test, y_test):
    print(f"\n--- Training {name} ---")
    start_time = time.time()
    
    # Grid Search for Hyperparameter Tuning
    grid_search = GridSearchCV(estimator=model, param_grid=params, cv=3, n_jobs=-1, verbose=1)
    grid_search.fit(X_train, y_train)
    
    best_model = grid_search.best_estimator_
    print(f"Best Parameters: {grid_search.best_params_}")
    
    # Cross-Validation Score
    cv_scores = cross_val_score(best_model, X_train, y_train, cv=5)
    print(f"Cross-Validation Accuracy (Mean): {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Evaluate on Test Set
    y_pred = best_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Set Accuracy: {accuracy:.4f}")
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (-1)', 'Phishing (1)']))
    
    training_time = time.time() - start_time
    print(f"Total Training Time: {training_time:.2f} seconds")
    
    return best_model, accuracy

print("Fetching dataset from UCI Repository...")
data = fetch_ucirepo(id=327)

X = data.data.features
y = data.data.targets.values.ravel()  

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("\nData split into training and testing sets:")
print("Training set size:", X_train.shape[0])
print("Testing set size:", X_test.shape[0])

# --- Model 1: Random Forest ---
rf_params = {
    'n_estimators': [50, 100],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5]
}
rf_model = RandomForestClassifier(random_state=42)
best_rf, rf_acc = train_and_evaluate_model("Random Forest", rf_model, rf_params, X_train, y_train, X_test, y_test)

# --- Model 2: Gradient Boosting ---
gb_params = {
    'n_estimators': [50, 100],
    'learning_rate': [0.1, 0.2],
    'max_depth': [3, 5]
}
gb_model = GradientBoostingClassifier(random_state=42)
best_gb, gb_acc = train_and_evaluate_model("Gradient Boosting", gb_model, gb_params, X_train, y_train, X_test, y_test)

# Compare and Save Best Model
print("\n--- Model Comparison ---")
print(f"Random Forest Accuracy: {rf_acc:.4f}")
print(f"Gradient Boosting Accuracy: {gb_acc:.4f}")

if gb_acc > rf_acc:
    print("\nGradient Boosting performed better. Saving Gradient Boosting model.")
    final_model = best_gb
else:
    print("\nRandom Forest performed better (or equal). Saving Random Forest model.")
    final_model = best_rf

model_filename = 'phishing_detector_model.joblib'
joblib.dump(final_model, model_filename)
print(f"\nBest trained model saved to '{model_filename}'")


from utils import extract_features_from_url


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
