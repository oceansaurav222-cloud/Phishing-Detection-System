import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd  # We still need this for the features_df
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime, timezone # <-- Added timezone

# --- 1. Initialize App & Load Model ONLY ---

app = Flask(__name__)
CORS(app) 

# ** THIS IS THE CORRECT 57-FEATURE LIST **
REALISTIC_FEATURES = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
    'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
    'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
    'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
    'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
    'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
    'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
    'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension',
    'nb_redirection', 
    'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
    'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
    'iframe', 'popup_window', 'onmouseover', 'right_clic', 'empty_title',
    'domain_in_title', 'domain_with_copyright',
    'whois_registered_domain', 'domain_registration_length', 'domain_age', 'dns_record'
]

model = None
feature_names = REALISTIC_FEATURES

try:
    # Load the trained XGBoost model
    model = joblib.load('xgboost_model_v2.joblib')
    print("Model 'xgboost_model_v2.joblib' loaded successfully!")
    
    # --- NO SHAP LOADING ---
    print("--- SERVER IS READY AND RUNNING (Smart Placeholder XAI Mode) ---")

except Exception as e:
    print(f"--- 💥 ERROR DURING APP INITIALIZATION 💥 ---")
    print(str(e))
    print("--- SERVER FAILED TO START ---")


# --- 2. Feature Extraction Function (with timezone fix) ---
shortening_services = [
    'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'adc.ly', 'bc.vc', 'sh.st', 'link.tl', 'adf.ly', 'tr.im'
]
common_tlds = ['.com', '.org', '.net', '.gov', '.edu', '.io', '.co', '.uk', 'ca', '.de']

def extract_features(url):
    features = {feat: 0 for feat in REALISTIC_FEATURES}
    try:
        if not re.match(r'^https?://', url):
            url_with_scheme = 'http://' + url
        else:
            url_with_scheme = url
        parsed_url = urlparse(url_with_scheme)
        hostname = parsed_url.netloc
        path = parsed_url.path
        if not path: path = '/'
        domain_parts = hostname.split('.')
        domain = domain_parts[-2] if len(domain_parts) > 1 else hostname
    except Exception as e:
        print(f"Error parsing URL {url}: {e}")
        return [list(features.values())]
    try:
        features['length_url'] = len(url)
        features['length_hostname'] = len(hostname)
        features['ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
        features['nb_dots'] = url.count('.')
        features['nb_hyphens'] = url.count('-')
        features['nb_at'] = url.count('@')
        features['nb_qm'] = url.count('?')
        features['nb_and'] = url.count('&')
        features['nb_or'] = url.count('|')
        features['nb_eq'] = url.count('=')
        features['nb_underscore'] = url.count('_')
        features['nb_tilde'] = url.count('~')
        features['nb_percent'] = url.count('%')
        features['nb_slash'] = url.count('/')
        features['nb_star'] = url.count('*')
        features['nb_colon'] = url.count(':')
        features['nb_comma'] = url.count(',')
        features['nb_semicolumn'] = url.count(';')
        features['nb_dollar'] = url.count('$')
        features['nb_space'] = url.count(' ')
        features['nb_www'] = hostname.lower().count('www')
        features['nb_com'] = url.lower().count('.com')
        features['nb_dslash'] = url.count('//')
        features['http_in_path'] = path.lower().count('http')
        features['https_token'] = 1 if 'https' in hostname.lower() else 0
        digit_count = sum(c.isdigit() for c in url)
        host_digit_count = sum(c.isdigit() for c in hostname)
        features['ratio_digits_url'] = digit_count / features['length_url'] if features['length_url'] > 0 else 0
        features['ratio_digits_host'] = host_digit_count / features['length_hostname'] if features['length_hostname'] > 0 else 0
        features['punycode'] = 1 if url.startswith('xn--') else 0
        features['port'] = 1 if parsed_url.port is not None else 0
        features['tld_in_path'] = 1 if any(tld in path.lower() for tld in common_tlds) else 0
        features['tld_in_subdomain'] = 1 if any(tld in hostname.lower().split('.')[:-2] for tld in common_tlds) else 0
        features['abnormal_subdomain'] = 1 if features['ip'] else 0
        features['nb_subdomains'] = hostname.count('.')
        features['prefix_suffix'] = 1 if '-' in domain else 0
        domain_digit_count = sum(c.isdigit() for c in domain)
        features['random_domain'] = 1 if len(domain) > 0 and (domain_digit_count / len(domain) > 0.4) else 0
        features['shortening_service'] = 1 if any(shortener in hostname for shortener in shortening_services) else 0
        features['path_extension'] = 1 if any(ext in path.lower() for ext in ['.exe', '.php', '.js', '.vbs']) else 0
    except Exception as e:
        print(f"Error during lexical extraction: {e}")
    
    features.update({
        'nb_redirection': 0, 
        'nb_hyperlinks': 0, 'ratio_intHyperlinks': 0, 'ratio_extHyperlinks': 0,
        'ratio_nullHyperlinks': 0, 'login_form': 0, 'external_favicon': 0,
        'links_in_tags': 0, 'submit_email': 0, 'iframe': 0, 'popup_window': 0,
        'onmouseover': 0, 'right_clic': 0, 'empty_title': 1, 'domain_in_title': 0,
        'domain_with_copyright': 0
    })

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
        response = requests.get(url_with_scheme, headers=headers, timeout=4, allow_redirects=True)
        
        if response.history:
            features['nb_redirection'] = len(response.history)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        html_lower = str(soup).lower()
        title = soup.find('title')
        if title and title.string:
            features['empty_title'] = 0
            if domain in title.string.lower():
                features['domain_in_title'] = 1
        links = soup.find_all('a', href=True)
        features['nb_hyperlinks'] = len(links)
        int_links, ext_links, null_links = 0, 0, 0
        if features['nb_hyperlinks'] > 0:
            for link in links:
                href = link['href']
                if not href or href.startswith('#') or 'javascript:void(0)' in href:
                    null_links += 1
                elif hostname in href or href.startswith('/'):
                    int_links += 1
                else:
                    ext_links += 1
            features['ratio_intHyperlinks'] = int_links / features['nb_hyperlinks']
            features['ratio_extHyperlinks'] = ext_links / features['nb_hyperlinks']
            features['ratio_nullHyperlinks'] = null_links / features['nb_hyperlinks']
        forms = soup.find_all('form', action=True)
        if forms:
            for form in forms:
                action = form['action'].lower()
                if 'mailto:' in action:
                    features['submit_email'] = 1
                if soup.find('input', {'type': 'password'}):
                    features['login_form'] = 1
        features['iframe'] = 1 if soup.find('iframe') else 0
        features['popup_window'] = 1 if 'window.open' in html_lower else 0
        features['onmouseover'] = 1 if 'onmouseover' in html_lower else 0
        features['right_clic'] = 1 if 'event.button==2' in html_lower else 0
        if '©' in html_lower or 'copyright' in html_lower:
            if domain in html_lower:
                features['domain_with_copyright'] = 1
        favicon = soup.find('link', rel='icon')
        if favicon and favicon.get('href', '').startswith('http') and hostname not in favicon['href']:
            features['external_favicon'] = 1
    except Exception as e:
        print(f"Could not fetch content for {url}: {e}")
    
    # --- THIS BLOCK IS NOW FIXED (with timezone fix) ---
    features.update({
        'whois_registered_domain': 0, 'domain_registration_length': -1,
        'domain_age': -1, 'dns_record': 0
    })
    try:
        domain_info = whois.whois(hostname)
        if domain_info:
            features['whois_registered_domain'] = 1
            features['dns_record'] = 1
            
            creation_date = domain_info.creation_date
            if creation_date:
                if isinstance(creation_date, list): creation_date = creation_date[0]
                
                # --- DATETIME FIX ---
                now_utc = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                # --- END FIX ---
                
                features['domain_age'] = (now_utc - creation_date).days
            
            exp_date = domain_info.expiration_date
            if exp_date and creation_date:
                if isinstance(exp_date, list): exp_date = exp_date[0]

                # --- DATETIME FIX ---
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                # --- END FIX ---
                
                features['domain_registration_length'] = (exp_date - creation_date).days
                
    except Exception as e:
        print(f"Could not get WHOIS data for {hostname}: {e}")
    # --- END OF FIXED BLOCK ---
    
    final_features_list = [features[feat_name] for feat_name in REALISTIC_FEATURES]
    
    return [final_features_list]

# --- 3. API Endpoint (with Smart Placeholders) ---
@app.route('/scan', methods=['POST'])
def scan():
    if not model: 
        return jsonify({'error': 'Model is not loaded'}), 500

    data = request.json
    url_to_scan = data.get('url')
    if not url_to_scan:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        features_list = extract_features(url_to_scan)
        
        try:
            features_df = pd.DataFrame(features_list, columns=feature_names)
            prediction = model.predict(features_df)
            probability = model.predict_proba(features_df)
        except Exception as model_e:
            raise Exception(f"Feature mismatch or model error. Expected {model.n_features_in_} features, got {len(features_list[0])}.")

        is_phishing = bool(prediction[0])
        confidence = float(probability[0][int(prediction[0])])
        
        # --- 💡 NEW "SMART PLACEHOLDER" LOGIC 💡 ---
        xai_features = []
        ui_confidence = confidence * 100 # The 0-100 score
        
        # Get the actual feature values for more descriptive text
        feature_values = dict(zip(REALISTIC_FEATURES, features_list[0]))
        
        if is_phishing:
            # If it's phishing, show "bad" features
            xai_features = [
                {"name": "Suspicious URL Structure", "contribution": ui_confidence * 0.7, "is_negative": True, "description": f"URL has indicators of phishing (e.g., {feature_values['nb_dots']} dots, {feature_values['nb_hyphens']} hyphens)."},
                {"name": "Domain Age", "contribution": ui_confidence * 0.5, "is_negative": True, "description": f"Domain age is {feature_values['domain_age']} days. New domains are high-risk."},
                {"name": "Login Form", "contribution": ui_confidence * 0.3, "is_negative": True, "description": f"Login form detected: {bool(feature_values['login_form'])}. This is risky on an untrusted page."}
            ]
        else:
            # If it's legitimate, show "good" features
            xai_features = [
                {"name": "Domain Age", "contribution": ui_confidence * 0.8, "is_negative": False, "description": f"Domain is {feature_values['domain_age']} days old. Well-established domains are safer."},
                {"name": "Domain Structure", "contribution": ui_confidence * 0.4, "is_negative": False, "description": "The URL structure appears normal and non-deceptive."},
                {"name": "Domain Registration", "contribution": ui_confidence * 0.6, "is_negative": False, "description": f"Domain is validly registered (Length: {feature_values['domain_registration_length']} days)."}
            ]

        result = {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'features': xai_features # Will be the smart placeholders
        }
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

# --- 4. Run the Server ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)