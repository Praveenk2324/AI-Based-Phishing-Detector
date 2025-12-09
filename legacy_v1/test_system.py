#!/usr/bin/env python3
"""
Test script for the Phishing Detection System
Tests both URL and Email detection endpoints
"""

import requests
import json

def test_url_detection():
    """Test URL phishing detection"""
    print("=== Testing URL Detection ===")
    
    test_urls = [
        "https://www.google.com",
        "http://bit.ly/suspicious-link",
        "http://182.121.11.23/login",
        "https://www.github.com"
    ]
    
    for url in test_urls:
        try:
            response = requests.post(
                "http://localhost:5000/predict",
                json={"type": "url", "url": url},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"URL: {url}")
                print(f"Result: {data['prediction_text']} (Confidence: {data['confidence']}%)")
                print(f"Risk Level: {data['risk_level']}")
                print("-" * 50)
            else:
                print(f"Error testing URL {url}: {response.status_code}")
                
        except Exception as e:
            print(f"Error testing URL {url}: {e}")

def test_email_detection():
    """Test Email phishing detection"""
    print("\n=== Testing Email Detection ===")
    
    test_emails = [
        {
            "content": "Subject: Urgent Action Required\n\nDear User,\n\nYour account has been suspended due to suspicious activity. Please click the link below to verify your account immediately.\n\nClick here: http://verify-account.com\n\nBest regards,\nSecurity Team",
            "expected": "Phishing"
        },
        {
            "content": "Subject: Monthly Newsletter\n\nHello,\n\nThank you for subscribing to our newsletter. Here are this month's updates and product announcements.\n\nBest regards,\nMarketing Team",
            "expected": "Legitimate"
        },
        {
            "content": "Subject: Order Confirmation\n\nDear Customer,\n\nThank you for your recent order. Your items will be shipped within 2-3 business days.\n\nOrder #12345\n\nRegards,\nCustomer Service",
            "expected": "Legitimate"
        }
    ]
    
    for i, email_data in enumerate(test_emails):
        try:
            response = requests.post(
                "http://localhost:5000/predict",
                json={"type": "email", "email": email_data["content"]},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"Email {i+1}: {data['prediction_text']} (Confidence: {data['confidence']}%)")
                print(f"Expected: {email_data['expected']}")
                print(f"Risk Level: {data['risk_level']}")
                print("-" * 50)
            else:
                print(f"Error testing email {i+1}: {response.status_code}")
                
        except Exception as e:
            print(f"Error testing email {i+1}: {e}")

def main():
    """Main test function"""
    print("Phishing Detection System - API Test")
    print("=" * 50)
    
    # Test if server is running
    try:
        response = requests.get("http://localhost:5000")
        if response.status_code == 200:
            print("[OK] Server is running!")
        else:
            print("[ERROR] Server is not responding properly")
            return
    except Exception as e:
        print(f"[ERROR] Cannot connect to server: {e}")
        print("Make sure to run 'python app.py' first")
        return
    
    # Run tests
    test_url_detection()
    test_email_detection()
    
    print("\n[SUCCESS] All tests completed!")
    print("\nWeb Interface: http://localhost:5000")
    print("API Endpoint: http://localhost:5000/predict")

if __name__ == "__main__":
    main()
