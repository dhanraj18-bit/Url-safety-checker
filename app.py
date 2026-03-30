import streamlit as st
import pandas as pd
import joblib
import time
import re
from urllib.parse import urlparse
import ipaddress

# 1. FEATURE EXTRACTION LOGIC
class FeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.path = ""
        self.scheme = ""
        try:
            parsed_url = urlparse(url)
            self.domain = parsed_url.netloc
            self.path = parsed_url.path
            self.scheme = parsed_url.scheme
        except:
            pass

    def _using_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return 1 # Phishing
        except ValueError:
            return -1 # Legitimate

    def _long_url(self):
        if len(self.url) < 54:
            return -1
        elif 54 <= len(self.url) <= 75:
            return 0
        else:
            return 1

    def _short_url(self):
        # The 'r' before the strings fixes the "invalid escape sequence \." warning
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          r'tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return 1
        return -1

    def _symbol_at(self):
        if "@" in self.url:
            return 1
        return -1

    def _redirecting_double_slash(self):
        if self.url.rfind('//') > 6:
            return 1
        return -1

    def _prefix_suffix_hyphen(self):
        if "-" in self.domain:
            return 1
        return -1

    def _sub_domains(self):
        dot_count = self.domain.count('.')
        if dot_count == 1:
            return -1
        elif dot_count == 2:
            return 0
        else:
            return 1

    def _https_token(self):
        if "https" in self.domain:
            return 1
        return -1

    def extract(self, feature_names):
        """Compiles all features into the exact format the model needs."""
        features_dict = {
            'UsingIP': self._using_ip(),
            'LongURL': self._long_url(),
            'ShortURL': self._short_url(),
            'Symbol@': self._symbol_at(),
            'Redirecting//': self._redirecting_double_slash(),
            'PrefixSuffix-': self._prefix_suffix_hyphen(),
            'SubDomains': self._sub_domains(),
            'HTTPS': -1 if self.scheme == 'https' else 1, 
            'HTTPSDomainURL': self._https_token(),
        }

        # Only return the specific features the model was trained on
        extracted_data = []
        for feature in feature_names:
            if feature in features_dict:
                extracted_data.append(features_dict[feature])
            else:
                extracted_data.append(0) # Fallback if missing
        
        return pd.DataFrame([extracted_data], columns=feature_names)

# 2. STREAMLIT FRONT END
st.set_page_config(page_title="URL Safety Checker", page_icon="🛡️", layout="centered")

@st.cache_resource
def load_model_data():
    try:
        model = joblib.load('phishing_detection_model.pkl')
        features = joblib.load('model_features.pkl')
        return model, features
    except Exception as e:
        st.error(f"Error loading model files: {e}")
        return None, None

model, feature_names = load_model_data()

st.title("URL Safety Checker")
st.markdown("Enter a website URL below to analyze whether it is safe or a potential phishing threat.")

# User Input
url_input = st.text_input("Website URL", placeholder="https://www.example.com")

if st.button("Analyze URL", type="primary"):
    if not url_input:
        st.warning("Please enter a URL first.")
    elif model is None:
        st.error("Model not loaded properly. Please run train_phishing_model.py first.")
    else:
        # Format URL for parsing
        if not url_input.startswith("http://") and not url_input.startswith("https://"):
            url_input = "http://" + url_input

        with st.spinner("Analyzing website features..."):
            time.sleep(0.8) # Small UI delay
            
            # Extract features and predict
            extractor = FeatureExtractor(url_input)
            website_features = extractor.extract(feature_names)
            prediction = model.predict(website_features)[0]
            
            st.divider()
            
            # Display Logic
            if prediction == 1:
                st.error("**WARNING: Potential Phishing Detected!**")
                st.write(f"The model analyzed the characteristics of `{url_input}` and flagged it as malicious.")
                
                # Show red flags
                st.write("**Red Flags Found:**")
                if extractor._long_url() == 1: st.write("- The URL is suspiciously long.")
                if extractor._prefix_suffix_hyphen() == 1: st.write("- The domain contains hyphens (common in spoofing).")
                if extractor._using_ip() == 1: st.write("- The URL uses a direct IP address instead of a domain name.")
                if extractor._symbol_at() == 1: st.write("- The URL contains an '@' symbol, hiding the true destination.")
                if extractor._short_url() == 1: st.write("- The URL uses a shortening service to hide the final destination.")
            else:
                st.success(" **Website appears safe.**")
                st.write(f"The model analyzed the characteristics of `{url_input}` and found no common phishing indicators.")

with st.sidebar:
    st.header("About the Tool")
    st.write("This application extracts lexical features from a URL and passes them to a custom Random Forest Machine Learning model to classify the site as Safe or Phishing.")
    st.caption("Model is optimized strictly on URL lexical characteristics.")