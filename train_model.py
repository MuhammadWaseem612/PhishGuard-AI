# train_model.py

import pandas as pd
import numpy as np
import nltk
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.metrics import (classification_report, confusion_matrix, 
                              accuracy_score, roc_auc_score, roc_curve)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
import warnings
warnings.filterwarnings('ignore')

# NLTK downloads
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
import re

print("=" * 60)
print("🛡️  PHISHING EMAIL DETECTION - MODEL TRAINING")
print("=" * 60)

# ============================================================
# DATASET LOADING
# ============================================================

def load_dataset():
    """
    Kaggle Dataset: 
    https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
    
    Ya phir:
    https://www.kaggle.com/datasets/subhajournal/phishingemails
    
    Download karke dataset/ folder mein rakh do
    """
    
    # Multiple dataset formats support
    possible_files = [
        'dataset/phishing_email.csv',
        'dataset/Phishing_Email.csv', 
        'dataset/emails.csv',
        'dataset/phishing_emails.csv'
    ]
    
    df = None
    for file in possible_files:
        if os.path.exists(file):
            df = pd.read_csv(file)
            print(f"✅ Dataset loaded: {file}")
            break
    
    if df is None:
        print("⚠️  Dataset not found! Generating sample dataset...")
        df = generate_sample_dataset()
    
    return df


def generate_sample_dataset():
    """Sample dataset agar Kaggle dataset na ho"""
    
    phishing_emails = [
        "URGENT: Your account has been compromised! Click here immediately to verify your identity and avoid suspension.",
        "Congratulations! You have won $1,000,000 lottery. Send your bank details to claim prize.",
        "Dear customer, your PayPal account is limited. Verify now: http://paypal-secure-login.xyz",
        "ALERT: Suspicious login detected on your Amazon account. Confirm identity now!",
        "Your Netflix subscription will be cancelled unless you update payment info immediately.",
        "Nigerian Prince needs your help to transfer $10 million. You will receive 30% commission.",
        "IRS Notice: You owe back taxes. Pay immediately to avoid arrest. Call now!",
        "Free iPhone giveaway! Click the link to claim your prize before it expires.",
        "Your email storage is full. Click here to upgrade for free and avoid losing emails.",
        "Bank of America: Your debit card has been frozen. Verify account details to unfreeze.",
        "WINNER: You have been selected for our exclusive reward program. Claim $500 gift card now!",
        "Microsoft security alert: Your Windows license has expired. Activate now to avoid data loss.",
        "Verify your Google account immediately or it will be permanently deleted within 24 hours.",
        "Your Apple ID has been used to make a purchase. If not you, click here to cancel.",
        "DHL delivery failed: Click link to reschedule. Package will be returned if not claimed.",
    ] * 20  # Multiply for more data
    
    legitimate_emails = [
        "Hi John, please find attached the quarterly report for your review. Let me know if you have questions.",
        "Team meeting scheduled for tomorrow at 10 AM in conference room B. Please confirm attendance.",
        "Your order #12345 has been shipped and will arrive by Friday. Track your package here.",
        "Monthly newsletter: Check out our latest blog posts and product updates for this month.",
        "Reminder: Your dentist appointment is scheduled for next Monday at 2 PM.",
        "Thank you for your purchase! Your receipt is attached. Contact us if you need assistance.",
        "Project deadline reminder: Please submit your work by end of day Thursday.",
        "Happy Birthday! Wishing you a wonderful day filled with joy and happiness.",
        "Your subscription has been renewed successfully. Thank you for continuing with us.",
        "Weekly team update: Great progress on all projects. See details in the attached document.",
        "Invoice #789 is due on the 15th. Please process payment at your earliest convenience.",
        "Your flight booking confirmation: Flight AA123 departing Monday at 8:30 AM from JFK.",
        "Lunch is on me today! Let's meet at the usual place at noon to discuss the project.",
        "Congratulations on your promotion! Looking forward to working with you in your new role.",
        "The library book you reserved is now available for pickup. You have 7 days to collect it.",
    ] * 20
    
    emails = phishing_emails + legitimate_emails
    labels = ['Phishing Email'] * len(phishing_emails) + ['Safe Email'] * len(legitimate_emails)
    
    df = pd.DataFrame({'Email Text': emails, 'Email Type': labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    os.makedirs('dataset', exist_ok=True)
    df.to_csv('dataset/sample_phishing_emails.csv', index=False)
    print("✅ Sample dataset generated and saved!")
    
    return df


# ============================================================
# TEXT PREPROCESSING  
# ============================================================

class EmailPreprocessor:
    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
    def clean_text(self, text):
        if pd.isna(text):
            return ""
        
        text = str(text).lower()
        
        # URLs remove
        text = re.sub(r'http\S+|www\S+|https\S+', ' url_link ', text)
        
        # Email addresses
        text = re.sub(r'\S+@\S+', ' email_addr ', text)
        
        # Phone numbers
        text = re.sub(r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', ' phone_num ', text)
        
        # Special characters
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        
        # Extra spaces
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stopwords and lemmatize
        tokens = [
            self.lemmatizer.lemmatize(token) 
            for token in tokens 
            if token not in self.stop_words and len(token) > 2
        ]
        
        return ' '.join(tokens)
    
    def extract_features(self, text):
        """Additional phishing-specific features"""
        features = {
            'has_url': 1 if re.search(r'http\S+|www\S+', str(text)) else 0,
            'url_count': len(re.findall(r'http\S+|www\S+', str(text))),
            'has_urgent_words': 1 if re.search(
                r'\b(urgent|immediately|verify|suspend|limited|expire|click|now)\b', 
                str(text).lower()
            ) else 0,
            'has_money': 1 if re.search(
                r'\$|\bmillion\b|\bprize\b|\bwinner\b|\bcash\b', 
                str(text).lower()
            ) else 0,
            'exclamation_count': str(text).count('!'),
            'caps_ratio': sum(1 for c in str(text) if c.isupper()) / (len(str(text)) + 1),
            'text_length': len(str(text)),
            'word_count': len(str(text).split()),
        }
        return features


# ============================================================
# MAIN TRAINING
# ============================================================

def train_models():
    # Load data
    df = load_dataset()
    
    print(f"\n📊 Dataset Shape: {df.shape}")
    print(f"📋 Columns: {df.columns.tolist()}")
    
    # Column name detect karo
    text_col = 'body'
    label_col = 'label'
    
    print(f"✅ Text Column: {text_col}")
    print(f"✅ Label Column: {label_col}")
    
    # Class distribution
    print(f"\n📈 Class Distribution:")
    print(df[label_col].value_counts())
    
    # Preprocessing
    print("\n🔄 Preprocessing emails...")
    preprocessor = EmailPreprocessor()
    df['cleaned_text'] = df[text_col].apply(preprocessor.clean_text)
    
    # Drop empty
    df = df.dropna(subset=['cleaned_text'])
    df = df[df['cleaned_text'].str.len() > 0]
    
    # Encode labels
    le = LabelEncoder()
    y = le.fit_transform(df[label_col])
    X = df['cleaned_text']
    
    print(f"✅ Classes: {le.classes_}")
    
    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n📦 Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    # ============================================================
    # MULTIPLE MODELS TRAINING
    # ============================================================
    
    models = {
        'Logistic Regression': Pipeline([
            ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
            ('clf', LogisticRegression(max_iter=1000, C=1.0))
        ]),
        'Random Forest': Pipeline([
            ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ]),
        'Naive Bayes': Pipeline([
            ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
            ('clf', MultinomialNB(alpha=0.1))
        ]),
        'Linear SVM': Pipeline([
            ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
            ('clf', LinearSVC(max_iter=2000))
        ]),
        'Gradient Boosting': Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ('clf', GradientBoostingClassifier(n_estimators=100, random_state=42))
        ]),
    }
    
    results = {}
    best_model = None
    best_accuracy = 0
    
    print("\n🏋️  Training Models...")
    print("=" * 50)
    
    for name, model in models.items():
        print(f"\n▶ Training: {name}")
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Cross validation
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
        
        results[name] = {
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'model': model,
            'predictions': y_pred
        }
        
        print(f"   ✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"   📊 CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_model = name
    
    print("\n" + "=" * 50)
    print(f"🏆 Best Model: {best_model} ({best_accuracy*100:.2f}%)")
    
    # ============================================================
    # SAVE MODELS
    # ============================================================
    
    os.makedirs('models', exist_ok=True)
    
    # Best model save
    best_pipeline = results[best_model]['model']
    joblib.dump(best_pipeline, 'models/best_model.pkl')
    joblib.dump(le, 'models/label_encoder.pkl')
    
    # All models save
    for name, result in results.items():
        filename = name.lower().replace(' ', '_')
        joblib.dump(result['model'], f'models/{filename}.pkl')
    
    print("✅ All models saved!")
    
    # ============================================================
    # EVALUATION REPORT
    # ============================================================
    
    print("\n📊 DETAILED EVALUATION REPORT")
    print("=" * 50)
    
    y_pred_best = results[best_model]['predictions']
    print(f"\n{best_model} - Classification Report:")
    print(classification_report(y_test, y_pred_best, target_names=['Legitimate', 'Phishing']))
    
    # Save results for API
    results_summary = {
        name: {
            'accuracy': float(res['accuracy']),
            'cv_mean': float(res['cv_mean']),
            'cv_std': float(res['cv_std'])
        }
        for name, res in results.items()
    }
    
    import json
    with open('models/training_results.json', 'w') as f:
        json.dump({
            'results': results_summary,
            'best_model': best_model,
            'best_accuracy': float(best_accuracy),
            'classes': le.classes_.tolist()
        }, f, indent=2)
    
    print("\n✅ Training Complete! Results saved.")
    
    # Confusion Matrix Plot
    save_plots(y_test, y_pred_best, le.classes_, best_model, results)
    
    return results, best_model


def save_plots(y_test, y_pred, classes, best_model_name, results):
    """Training visualizations"""
    
    os.makedirs('static/plots', exist_ok=True)
    
    # 1. Confusion Matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_title(f'Confusion Matrix - {best_model_name}', fontsize=14, fontweight='bold')
    ax.set_ylabel('Actual', fontsize=12)
    ax.set_xlabel('Predicted', fontsize=12)
    plt.tight_layout()
    plt.savefig('static/plots/confusion_matrix.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    # 2. Model Comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    model_names = list(results.keys())
    accuracies = [results[m]['accuracy'] for m in model_names]
    colors = ['#ff4444' if m == best_model_name else '#4a90d9' for m in model_names]
    
    bars = ax.bar(model_names, [a * 100 for a in accuracies], color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Models', fontsize=12)
    ax.set_ylabel('Accuracy (%)', fontsize=12)
    ax.set_title('Model Comparison', fontsize=14, fontweight='bold')
    ax.set_ylim([min(accuracies) * 95, 101])
    ax.tick_params(axis='x', rotation=15)
    
    for bar, acc in zip(bars, accuracies):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.1,
                f'{acc*100:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    ax.axhline(y=90, color='red', linestyle='--', alpha=0.5, label='90% threshold')
    ax.legend()
    plt.tight_layout()
    plt.savefig('static/plots/model_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    print("✅ Plots saved to static/plots/")


if __name__ == "__main__":
    train_models()