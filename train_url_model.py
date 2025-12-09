import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

def train_url_model():
    print("Loading dataset...")
    # Using 'error_bad_lines=False' or 'on_bad_lines=skip' depending on pandas version if there are issues, 
    # but for now standard read should work if file is clean.
    try:
        df = pd.read_csv("phishing_site_urls.csv")
    except FileNotFoundError:
        print("Error: phishing_site_urls.csv not found.")
        return

    print(f"Dataset Shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")

    # Identify columns (assuming standard format or derived from previous knowledge)
    # The dataset usually has 'URL' and 'Label'
    if 'URL' in df.columns and 'Label' in df.columns:
        X = df['URL']
        y = df['Label']
    else:
        # Fallback or error if columns don't match expectation
        print("Unexpected column names. Expecting 'URL' and 'Label'.")
        # Try to find them dynamically
        url_col = next((col for col in df.columns if 'url' in col.lower()), None)
        label_col = next((col for col in df.columns if 'label' in col.lower() or 'type' in col.lower()), None)
        
        if url_col and label_col:
            X = df[url_col]
            y = df[label_col]
        else:
            print("Could not identify URL and Label columns.")
            return

    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Vectorizing URLs (Character-level TF-IDF)...")
    # Using character-level analyzer to capture sub-token patterns
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=50000)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    print("Training Logistic Regression Model...")
    # Logistic Regression is generally very effective for this high-dimensional sparse data
    model = LogisticRegression(max_iter=1000, n_jobs=-1)
    model.fit(X_train_tfidf, y_train)

    print("Evaluating Model...")
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("Saving model and vectorizer...")
    joblib.dump(model, 'url_model.joblib')
    joblib.dump(vectorizer, 'url_vectorizer.joblib')
    print("Saved 'url_model.joblib' and 'url_vectorizer.joblib' successfully.")

if __name__ == "__main__":
    train_url_model()
