import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import re
import requests
import zipfile
import os
from email import message_from_string
import email.utils

def download_spam_dataset():
    """Download and extract spam dataset"""
    print("Downloading spam dataset...")
    
    # URLs for spam datasets
    spam_urls = [
        "https://archive.ics.uci.edu/ml/machine-learning-databases/spambase/spambase.data",
        "https://archive.ics.uci.edu/ml/machine-learning-databases/spambase/spambase.names"
    ]
    
    # Create data directory
    os.makedirs('email_data', exist_ok=True)
    
    # Download spam data
    try:
        response = requests.get(spam_urls[0])
        with open('email_data/spambase.data', 'wb') as f:
            f.write(response.content)
        print("Spam dataset downloaded successfully!")
        return True
    except Exception as e:
        print(f"Error downloading spam dataset: {e}")
        return False

def create_synthetic_email_dataset():
    """Create a comprehensive synthetic email dataset for training"""
    print("Creating synthetic email dataset...")
    
    # Extensive phishing email patterns
    phishing_patterns = [
        # Urgency tactics
        "urgent action required", "immediate attention needed", "act now or lose",
        "limited time offer", "expires today", "deadline approaching",
        
        # Account-related
        "verify your account", "account suspended", "account will be closed",
        "unauthorized access", "security breach detected", "login attempt failed",
        "password expired", "account verification required", "confirm your identity",
        
        # Suspicious requests
        "click here immediately", "click below to verify", "follow this link",
        "update your information", "confirm your details", "validate your account",
        "restore your access", "unlock your account", "reactivate your profile",
        
        # Threats and warnings
        "your account will be deleted", "service will be terminated",
        "access will be revoked", "account permanently suspended",
        "immediate action required", "failure to respond",
        
        # Financial phishing
        "payment required", "billing issue", "credit card expired",
        "bank account suspended", "transaction failed", "payment overdue",
        "refund available", "claim your money", "free money offer",
        
        # Social engineering
        "congratulations you won", "claim your prize", "you are selected",
        "exclusive offer", "special promotion", "limited time deal",
        "act fast", "don't miss out", "last chance"
    ]
    
    # Legitimate email patterns
    legitimate_patterns = [
        # Professional communications
        "thank you for", "welcome to", "newsletter", "monthly report",
        "order confirmation", "receipt", "invoice", "delivery update",
        "appointment reminder", "meeting scheduled", "news update",
        "product update", "service announcement", "regular update",
        
        # Business communications
        "project update", "team meeting", "quarterly report",
        "annual review", "performance evaluation", "budget proposal",
        "client meeting", "contract renewal", "service agreement",
        
        # Educational content
        "course announcement", "assignment due", "exam schedule",
        "grade posted", "academic calendar", "scholarship opportunity",
        "research findings", "study group", "library notice",
        
        # Personal communications
        "birthday wishes", "holiday greetings", "family update",
        "vacation photos", "party invitation", "wedding announcement",
        "baby announcement", "graduation celebration", "retirement party",
        
        # Service notifications
        "system maintenance", "service upgrade", "new feature available",
        "bug fix released", "security update", "privacy policy update",
        "terms of service", "user agreement", "account settings"
    ]
    
    emails = []
    labels = []
    
    # Generate phishing emails
    for pattern in phishing_patterns:
        # Create multiple variations of each pattern
        variations = [
            f"Subject: {pattern.title()}\n\nDear User,\n\n{pattern}. Please click the link below to verify your account immediately.\n\nClick here: http://verify-account.com\n\nBest regards,\nSecurity Team",
            f"Subject: URGENT - {pattern.title()}\n\nHello,\n\nWe have detected suspicious activity on your account. {pattern}. Please respond immediately.\n\nVerify now: http://secure-login.net\n\nRegards,\nAccount Security",
            f"Subject: Action Required - {pattern.title()}\n\nDear Customer,\n\n{pattern}. Failure to respond within 24 hours will result in account suspension.\n\nAct now: http://account-verify.org\n\nSincerely,\nSupport Team"
        ]
        
        for variation in variations:
            emails.append(variation)
            labels.append(1)  # Phishing
    
    # Generate legitimate emails
    for pattern in legitimate_patterns:
        variations = [
            f"Subject: {pattern.title()}\n\nHello,\n\nThis is a {pattern} from our service. We hope you find this information helpful.\n\nBest regards,\nTeam",
            f"Subject: {pattern.title()}\n\nDear User,\n\nThank you for your continued support. Here's your {pattern}.\n\nRegards,\nAdministration",
            f"Subject: {pattern.title()}\n\nHi there,\n\nWe're pleased to share this {pattern} with you. Please let us know if you have any questions.\n\nBest,\nSupport Team"
        ]
        
        for variation in variations:
            emails.append(variation)
            labels.append(0)  # Legitimate
    
    return emails, labels

def extract_email_features(email_text):
    """Extract additional features from email text"""
    features = []
    
    # Basic text features
    features.append(len(email_text))  # Email length
    features.append(email_text.count('!'))  # Exclamation marks
    features.append(email_text.count('?'))  # Question marks
    features.append(email_text.count('$'))  # Dollar signs
    features.append(email_text.count('@'))  # At symbols
    
    # Suspicious patterns
    suspicious_words = ['urgent', 'immediate', 'click', 'verify', 'suspended', 'expired', 'free', 'winner', 'congratulations']
    features.append(sum(1 for word in suspicious_words if word.lower() in email_text.lower()))
    
    # URL patterns
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_text)
    features.append(len(urls))  # Number of URLs
    
    # Email patterns
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, email_text)
    features.append(len(emails))  # Number of email addresses
    
    # Caps ratio
    caps_count = sum(1 for c in email_text if c.isupper())
    features.append(caps_count / len(email_text) if len(email_text) > 0 else 0)
    
    return features

def load_spam_dataset():
    """Load the UCI spam dataset"""
    try:
        # Load spam dataset
        spam_data = pd.read_csv('email_data/spambase.data', header=None)
        
        # The last column is the label (1 for spam, 0 for ham)
        X_spam = spam_data.iloc[:, :-1]  # Features
        y_spam = spam_data.iloc[:, -1]    # Labels
        
        print(f"Spam dataset loaded: {len(X_spam)} samples")
        return X_spam, y_spam
    except Exception as e:
        print(f"Error loading spam dataset: {e}")
        return None, None

def main():
    print("=== Email Phishing Detection Model Training ===")
    
    # Try to download real dataset
    real_data_available = download_spam_dataset()
    
    # Always use synthetic dataset for TF-IDF-based email analysis
    # This ensures we have text-based features compatible with the web app
    print("\nUsing synthetic email dataset for TF-IDF-based training...")
    
    # Fallback to synthetic dataset
    print("\nUsing synthetic email dataset for training...")
    
    # Create synthetic dataset
    emails, labels = create_synthetic_email_dataset()
    
    print(f"Created {len(emails)} synthetic emails")
    print(f"Phishing emails: {sum(labels)}")
    print(f"Legitimate emails: {len(labels) - sum(labels)}")
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        emails, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    print(f"\nTraining set size: {len(X_train)}")
    print(f"Testing set size: {len(X_test)}")
    
    # Create TF-IDF vectorizer
    print("\nCreating TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=2000,
        stop_words='english',
        ngram_range=(1, 2),  # Include bigrams
        min_df=2,
        max_df=0.95
    )
    
    # Transform text to features
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    print(f"TF-IDF features: {X_train_tfidf.shape[1]}")
    
    # Train Random Forest model
    print("\nTraining Random Forest model...")
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        max_features='sqrt',
        oob_score=True,
        random_state=42
    )
    rf_classifier.fit(X_train_tfidf, y_train)
    
    # Evaluate model
    print("Model training completed.")
    print(f"Out-of-Bag Score: {rf_classifier.oob_score_:.4f}")
    
    y_pred = rf_classifier.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))
    
    # Save model and vectorizer
    model_filename = 'email_phishing_model.joblib'
    vectorizer_filename = 'email_vectorizer.joblib'
    
    joblib.dump(rf_classifier, model_filename)
    joblib.dump(vectorizer, vectorizer_filename)
    
    print(f"\nTrained model saved to '{model_filename}'")
    print(f"Vectorizer saved to '{vectorizer_filename}'")
    
    # Test with sample emails
    print("\n=== Testing with Sample Emails ===")
    
    test_emails = [
        "Subject: Urgent Action Required\n\nDear User,\n\nYour account has been suspended due to suspicious activity. Please click the link below to verify your account immediately.\n\nClick here: http://verify-account.com\n\nBest regards,\nSecurity Team",
        "Subject: Monthly Newsletter\n\nHello,\n\nThank you for subscribing to our newsletter. Here are this month's updates and product announcements.\n\nBest regards,\nMarketing Team",
        "Subject: Order Confirmation\n\nDear Customer,\n\nThank you for your recent order. Your items will be shipped within 2-3 business days.\n\nOrder #12345\n\nRegards,\nCustomer Service"
    ]
    
    for i, email in enumerate(test_emails):
        email_features = vectorizer.transform([email])
        prediction = rf_classifier.predict(email_features)[0]
        probability = rf_classifier.predict_proba(email_features)[0]
        confidence = max(probability) * 100
        
        result = "Phishing" if prediction == 1 else "Legitimate"
        print(f"\nTest Email {i+1}: {result} (Confidence: {confidence:.2f}%)")
        print(f"Content: {email[:100]}...")

if __name__ == "__main__":
    main()
