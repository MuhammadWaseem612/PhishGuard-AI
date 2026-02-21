# app.py

from flask import Flask, render_template, request, jsonify
import joblib
import json
import os
import re
import nltk
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

nltk.download('stopwords', quiet=True)
nltk.download('punkt', quiet=True)
nltk.download('wordnet', quiet=True)

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

app = Flask(__name__)

# ============================================================
# LOAD MODELS
# ============================================================

def load_models():
    models = {}
    model_files = {
        'Best Model': 'models/best_model.pkl',
        'Logistic Regression': 'models/logistic_regression.pkl',
        'Random Forest': 'models/random_forest.pkl',
        'Naive Bayes': 'models/naive_bayes.pkl',
        'Linear SVM': 'models/linear_svm.pkl',
        'Gradient Boosting': 'models/gradient_boosting.pkl',
    }
    
    for name, path in model_files.items():
        if os.path.exists(path):
            try:
                models[name] = joblib.load(path)
            except:
                pass
    
    label_encoder = None
    if os.path.exists('models/label_encoder.pkl'):
        label_encoder = joblib.load('models/label_encoder.pkl')
    
    training_results = {}
    if os.path.exists('models/training_results.json'):
        with open('models/training_results.json', 'r') as f:
            training_results = json.load(f)
    
    return models, label_encoder, training_results


# Global variables
MODELS, LABEL_ENCODER, TRAINING_RESULTS = {}, None, {}

try:
    MODELS, LABEL_ENCODER, TRAINING_RESULTS = load_models()
    print(f"✅ Models loaded: {list(MODELS.keys())}")
except Exception as e:
    print(f"⚠️ Model loading error: {e}")


# ============================================================
# PREPROCESSING
# ============================================================

class EmailAnalyzer:
    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        try:
            self.stop_words = set(stopwords.words('english'))
        except:
            self.stop_words = set()
    
    def clean_text(self, text):
        if not text:
            return ""
        text = str(text).lower()
        text = re.sub(r'http\S+|www\S+|https\S+', ' url_link ', text)
        text = re.sub(r'\S+@\S+', ' email_addr ', text)
        text = re.sub(r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', ' phone_num ', text)
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        
        try:
            tokens = word_tokenize(text)
        except:
            tokens = text.split()
        
        tokens = [
            self.lemmatizer.lemmatize(token)
            for token in tokens
            if token not in self.stop_words and len(token) > 2
        ]
        return ' '.join(tokens)
    
    def analyze_email(self, email_text):
        """Comprehensive email analysis"""
        text = str(email_text)
        text_lower = text.lower()
        
        # Phishing indicators
        phishing_keywords = {
            'urgent': ['urgent', 'immediately', 'asap', 'right now', 'act now'],
            'verify': ['verify', 'confirm', 'validate', 'authenticate'],
            'threat': ['suspend', 'terminate', 'cancel', 'delete', 'expire', 'locked'],
            'money': ['prize', 'winner', 'lottery', 'million', 'cash', 'reward', '$', '€'],
            'click': ['click here', 'click now', 'follow this link', 'download now'],
            'personal': ['password', 'ssn', 'social security', 'credit card', 'bank account'],
        }
        
        found_indicators = {}
        total_score = 0
        
        for category, keywords in phishing_keywords.items():
            found = [kw for kw in keywords if kw in text_lower]
            if found:
                found_indicators[category] = found
                total_score += len(found)
        
        # URL analysis
        urls = re.findall(r'http[s]?://\S+|www\.\S+', text)
        suspicious_urls = [url for url in urls if any(
            x in url.lower() for x in ['bit.ly', 'tinyurl', 'goo.gl', 'secure-login', 'verify-account']
        )]
        
        # Text metrics
        caps_ratio = sum(1 for c in text if c.isupper()) / (len(text) + 1)
        exclamation_count = text.count('!')
        question_count = text.count('?')
        
        return {
            'phishing_indicators': found_indicators,
            'urls_found': urls,
            'suspicious_urls': suspicious_urls,
            'caps_ratio': round(caps_ratio * 100, 2),
            'exclamation_count': exclamation_count,
            'question_count': question_count,
            'word_count': len(text.split()),
            'char_count': len(text),
            'risk_score': min(total_score * 10, 100)
        }


analyzer = EmailAnalyzer()


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    model_names = list(MODELS.keys()) if MODELS else ['No models loaded']
    stats = {
        'total_models': len(MODELS),
        'best_accuracy': TRAINING_RESULTS.get('best_accuracy', 0),
        'best_model': TRAINING_RESULTS.get('best_model', 'N/A'),
    }
    return render_template('index.html', models=model_names, stats=stats)


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        email_text = data.get('email_text', '').strip()
        selected_model = data.get('model', 'Best Model')
        
        if not email_text:
            return jsonify({'error': 'Email text is required!'}), 400
        
        if not MODELS:
            return jsonify({'error': 'No models loaded! Please train first.'}), 500
        
        # Use selected or best model
        model_key = selected_model if selected_model in MODELS else list(MODELS.keys())[0]
        model = MODELS[model_key]
        
        # Preprocess
        cleaned_text = analyzer.clean_text(email_text)
        
        # Predict
        prediction = model.predict([cleaned_text])[0]
        
        # Probability (if available)
        confidence = 0.0
        try:
            proba = model.predict_proba([cleaned_text])[0]
            confidence = round(float(max(proba)) * 100, 2)
        except:
            confidence = 85.0  # Default for models without predict_proba
        
        # Decode label
        # Decode label
        if LABEL_ENCODER is not None:
            try:
                predicted_label = LABEL_ENCODER.inverse_transform([prediction])[0]
            except:
                predicted_label = str(prediction)
        else:
            predicted_label = str(prediction)
        
        # Determine if phishing
        predicted_label = str(predicted_label)
        is_phishing = predicted_label == '1' or any(word in predicted_label.lower() for word in ['phishing', 'spam', 'malicious'])
        
        # Email analysis
        analysis = analyzer.analyze_email(email_text)
        
        # Adjust confidence based on risk score
        final_confidence = (confidence + analysis['risk_score']) / 2 if is_phishing else confidence
        final_confidence = min(final_confidence, 99.9)
        
        return jsonify({
            'success': True,
            'prediction': predicted_label,
            'is_phishing': is_phishing,
            'confidence': round(final_confidence, 2),
            'model_used': model_key,
            'analysis': analysis,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'email_preview': email_text[:100] + '...' if len(email_text) > 100 else email_text,
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/models', methods=['GET'])
def get_models():
    model_info = {}
    
    if TRAINING_RESULTS and 'results' in TRAINING_RESULTS:
        for name, data in TRAINING_RESULTS['results'].items():
            model_info[name] = {
                'accuracy': round(data.get('accuracy', 0) * 100, 2),
                'cv_score': round(data.get('cv_mean', 0) * 100, 2),
                'status': 'loaded' if name in MODELS else 'not_loaded'
            }
    
    return jsonify({
        'models': model_info,
        'best_model': TRAINING_RESULTS.get('best_model', 'N/A'),
        'total_models': len(MODELS),
        'classes': TRAINING_RESULTS.get('classes', [])
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'models_loaded': len(MODELS),
        'best_accuracy': round(TRAINING_RESULTS.get('best_accuracy', 0) * 100, 2),
        'best_model': TRAINING_RESULTS.get('best_model', 'N/A'),
        'models_available': list(MODELS.keys()),
        'system_status': 'operational' if MODELS else 'training_required'
    })


@app.route('/api/sample-emails', methods=['GET'])
def sample_emails():
    samples = {
        'phishing': [
            "URGENT: Your bank account has been compromised! Click here immediately to verify your identity: http://secure-login-verify.xyz/account",
            "Congratulations! You have been selected as our lucky winner of $1,000,000! Claim your prize now by sending your personal details.",
            "Your PayPal account is limited. Verify your account now to avoid permanent suspension: http://paypal-verify.fake.com",
        ],
        'legitimate': [
            "Hi Sarah, just wanted to follow up on our meeting from yesterday. Please review the attached project proposal and share your feedback.",
            "Your order #ORD-2024-789 has been successfully placed. Estimated delivery: 3-5 business days. Thank you for shopping with us!",
            "Team reminder: Monthly review meeting is scheduled for Friday at 2 PM in the main conference room. Please come prepared with your reports.",
        ]
    }
    return jsonify(samples)


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🛡️  PHISHING EMAIL DETECTOR")
    print("="*50)
    print(f"📦 Models loaded: {len(MODELS)}")
    print("🌐 Server starting at: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)