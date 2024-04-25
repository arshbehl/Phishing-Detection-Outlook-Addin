# Import necessary libraries
from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from werkzeug.utils import secure_filename
import os
import re
import hashlib
import requests
import socket
import time
import urllib.parse
from virus_total_apis import PublicApi as VirusTotalPublicApi
import whois
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import nltk

# Initialize Flask app
app = Flask(__name__)

# Initialize NLTK resources (downloads if needed)
try:
    nltk.data.find('punkt')
    nltk.data.find('stopwords')
    nltk.data.find('vader_lexicon')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('vader_lexicon')

# Initialize sentiment analyzer
sid = SentimentIntensityAnalyzer()

# Replace with your actual VirusTotal API key
VT_API_KEY = '649441bb015c899386431e00f3a770fe878819f51d80760275a8439464c61495'


def extract_text_from_html(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        # Extract text from all paragraphs (p tags) in the HTML content
        paragraphs = soup.find_all('p')
        extracted_text = '\n'.join([p.get_text() for p in paragraphs])
        return extracted_text
    except Exception as e:
        return str(e)

def analyze_email(email_data):
    try:
        email_text = extract_text_from_html(email_data)

        # Perform sentiment analysis
        sentiment_scores = sid.polarity_scores(email_text)

        # Perform phishing detection using custom logic
        is_phishing_email = predict_phishing(email_text)

        # Extract URLs from email content
        urls = extract_urls(email_text)

        # Analyze each URL
        url_results = {}
        for url in urls:
            url_data = analyze_url(url)
            url_results[url] = url_data
            time.sleep(1)  # Introduce a delay between URL analyses
            
        # Extract and analyze attachments
        attachments = request.files.getlist('attachments')  # Assuming attachments are sent as files
        attachment_results = []
        for attachment in attachments:
            attachment_data = analyze_attachment(attachment)
            attachment_results.append(attachment_data)

        results = {
            "sentiment_scores": sentiment_scores,
            "is_phishing_email": is_phishing_email,
            "url_results": url_results,
            "attachment_results": attachment_results
        }

        return results

    except Exception as e:
        return {"error": str(e)}


# Function to handle file uploads
def analyze_attachment(attachments):
    # Implement logic to analyze the attachment
    attachment_data = []
    for attachment in attachments:
        filename = secure_filename(attachment.filename)
        attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        attachment_data.append({
            "filename": filename,
            "content_type": attachment.content_type,
            "size": len(attachment.read()),
            "is_inline": attachment.is_inline
        })
    return attachment_data



def predict_phishing(email_text):
    # Preprocess email text
    preprocessed_text = preprocess_text(email_text)

    # Extract features from preprocessed text
    features = extract_features(preprocessed_text)

    # Apply custom logic for phishing detection
    if features['sentiment_compound'] < 0 or features['contains_phishing_keywords']:
        return True
    else:
        return False

def preprocess_text(text):
    # Tokenize text into words
    tokens = word_tokenize(text.lower())

    # Remove stopwords and punctuation
    stop_words = set(stopwords.words('english'))
    filtered_tokens = [token for token in tokens if token not in stop_words and token.isalpha()]

    # Join filtered tokens back into text
    preprocessed_text = ' '.join(filtered_tokens)

    return preprocessed_text

def extract_features(text):
    # Perform sentiment analysis using NLTK
    sentiment_scores = sid.polarity_scores(text)

    # Calculate presence of phishing-related keywords
    contains_phishing_keywords = any(word in text.lower() for word in ['password', 'account', 'urgent', 'verify', 'click', 'login', 'security'])

    features = {
        "sentiment_compound": sentiment_scores['compound'],
        "contains_phishing_keywords": contains_phishing_keywords
    }

    return features

def extract_urls(text):
    # Use regex to extract URLs from text
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    return urls

def analyze_url(url):
    try:
        vt = VirusTotalPublicApi(VT_API_KEY)
        parsed_url = urllib.parse.urlparse(url)
        domain_info = parsed_url.netloc

        # Get IP addresses for domain
        ip_addresses = socket.gethostbyname_ex(domain_info)[2]

        # VirusTotal URL report
        response = vt.get_url_report(url)

        # SSL/TLS Certificate Info
        cert = ssl.get_server_certificate((parsed_url.hostname, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        cert_info = {
            "issuer": x509_cert.issuer.rfc4514_string(),
            "subject": x509_cert.subject.rfc4514_string(),
            "valid_from": x509_cert.not_valid_before,
            "valid_until": x509_cert.not_valid_after
        }

        # WHOIS Lookup
        whois_info = whois.whois(domain_info)

        # URL redirection and final destination
        final_url = url
        redirect_chain = []
        while True:
            response = requests.get(final_url, allow_redirects=False)
            if response.status_code == 301 or response.status_code == 302:
                redirect_url = response.headers.get('Location')
                redirect_chain.append(redirect_url)
                final_url = redirect_url
            else:
                break

        # Determine URL safety based on VirusTotal report
        is_safe_url = response['results']['response_code'] == 1 and response['results']['positives'] == 0

        url_data = {
            "domain_info": domain_info,
            "ip_addresses": ip_addresses,
            "virus_total_report": response,
            "ssl_tls_certificate_info": cert_info,
            "whois_info": whois_info,
            "redirect_chain": redirect_chain,
            "is_safe_url": is_safe_url
        }

        return url_data

    except Exception as e:
        return {"error": str(e)}


@app.route('/')
def index():
    return render_template('final.html')


# Endpoint for email analysis
@app.route('/analyze-email', methods=['POST'])
def analyze_email_route():
    try:
        data = request.json
        email_content = data.get('email_content', '')
        attachments = request.files.getlist('attachments')  # Get attachments

        if email_content:
            analysis_results = analyze_email(email_content, attachments)
            return jsonify(analysis_results)
        else:
            return jsonify({"error": "No email content provided"})

    except Exception as e:
        return jsonify({"error": str(e)})

# Run Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
