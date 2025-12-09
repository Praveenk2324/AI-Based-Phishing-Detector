import kagglehub
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import glob

def train_kaggle_model():
    print("Downloading dataset from Kaggle...")
    # Download latest version
    path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
    print("Path to dataset files:", path)
    
    # Find the CSV file in the downloaded folder
    csv_files = glob.glob(os.path.join(path, "*.csv"))
    if not csv_files:
        print("Error: No CSV file found in the downloaded dataset.")
        return
    
    csv_path = csv_files[0]
    print(f"Loading data from: {csv_path}")
    
    # Load dataset
    # Dataset likely has 'URL' and 'Label' (or similar) columns
    try:
        df = pd.read_csv(csv_path)
        print("Dataset loaded successfully.")
        print(f"Shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return

    # Basic cleanup
    # Check for likely column names
    url_col = None
    label_col = None
    
    possible_url_cols = ['URL', 'url', 'domain', 'website']
    possible_label_cols = ['Label', 'label', 'class', 'Class', 'Type']
    
    for col in df.columns:
        if col in possible_url_cols:
            url_col = col
        if col in possible_label_cols:
            label_col = col
            
    if not url_col or not label_col:
        print(f"Error: Could not automatically detect URL or Label columns. Found: {df.columns.tolist()}")
        return
        
    print(f"Using URL column: {url_col}")
    print(f"Using Label column: {label_col}")
    
    # Preprocessing
    print("Preprocessing data...")
    X = df[url_col]
    y = df[label_col]
    
    # Split data
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Vectorization
    print("Vectorizing URLs (TF-IDF)...")
    # Using character-level TF-IDF mainly for URL structure patterns
    # Removed lambda functions to avoid PicklingError
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=5000, min_df=5, max_df=0.9)
    # Note: 'char' analyzer with ngrams is very effective for URLs to capture sub-patterns like '.com', 'http', 'secure' etc.
    # However, for speed on large datasets, maybe 'word' or simple tokens?
    # Let's try flexible 'char_wb' or just 'char' to capture string patterns.
    # Actually, the user asked for "suitable algorithm". 
    # Let's use the 'char' analyzer which works well for URLs even if slightly slower.
    
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Model Training
    print("Training Logistic Regression Model...")
    # Logistic Regression is fast and effective for high-dimensional text data
    model = LogisticRegression(max_iter=1000, n_jobs=-1, solver='saga')
    model.fit(X_train_tfidf, y_train)
    
    # Evaluation
    print("Evaluating model...")
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save Model
    print("Saving model and vectorizer...")
    joblib.dump(model, 'kaggle_phishing_model.joblib')
    joblib.dump(vectorizer, 'kaggle_vectorizer.joblib')
    print("Model saved to 'kaggle_phishing_model.joblib'")
    print("Vectorizer saved to 'kaggle_vectorizer.joblib'")
    
    # Test Prediction
    print("\n--- Testing with Sample URLs ---")
    samples = [
        "https://www.google.com",
        "http://phishing-bank-login.com/secure",
        "https://www.kaggle.com",
        "http://192.168.1.1/login"
    ]
    
    transformed_samples = vectorizer.transform(samples)
    predictions = model.predict(transformed_samples)
    
    for url, pred in zip(samples, predictions):
        print(f"URL: {url} -> Prediction: {pred}")

if __name__ == "__main__":
    train_kaggle_model()
