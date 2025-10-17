"""
CyberForensics Pro - Complete Digital Forensics Platform
Main Application File: app.py

Install required packages:
pip install streamlit pandas plotly requests beautifulsoup4 python-whois dnspython numpy scikit-learn xgboost lightgbm transformers torch Pillow reportlab

Usage: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import json
import base64
from io import BytesIO
import time
import re
import requests
from urllib.parse import urlparse, parse_qs
import socket
import ssl
import dns.resolver
import whois
from bs4 import BeautifulSoup
import pickle
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import warnings
warnings.filterwarnings('ignore')

# Try to import transformers for LLM
try:
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch
    HAS_TRANSFORMERS = True
except:
    HAS_TRANSFORMERS = False

# ==================== PAGE CONFIGURATION ====================
st.set_page_config(
    page_title="CyberForensics Pro",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    .main {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        padding: 0;
    }
    
    .cyber-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    .cyber-header h1 {
        color: #ffffff;
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .cyber-header p {
        color: #e0e0e0;
        font-size: 1.1rem;
        margin-top: 0.5rem;
    }
    
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.1);
        border: 2px solid rgba(255,255,255,0.2);
        border-radius: 10px;
        color: white;
        font-size: 1.1rem;
        padding: 1rem;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #667eea;
        box-shadow: 0 0 20px rgba(102,126,234,0.5);
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.75rem 2rem;
        font-size: 1.1rem;
        font-weight: 600;
        width: 100%;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(102,126,234,0.5);
    }
    
    .metric-card {
        background: linear-gradient(135deg, rgba(102,126,234,0.1) 0%, rgba(118,75,162,0.1) 100%);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        padding: 1.5rem;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        margin-bottom: 1rem;
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.5rem 1.5rem;
        border-radius: 25px;
        font-weight: 600;
        font-size: 1rem;
        margin: 0.5rem;
    }
    
    .safe-badge {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
    }
    
    .warning-badge {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
    }
    
    .danger-badge {
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        color: white;
    }
    
    .section-header {
        color: #667eea;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 2rem 0 1rem 0;
        border-bottom: 2px solid #667eea;
        padding-bottom: 0.5rem;
    }
    
    .info-text {
        color: #e0e0e0;
        font-size: 1rem;
        line-height: 1.6;
    }
    
    .stProgress > div > div > div {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    div[data-testid="stExpander"] {
        background: rgba(255,255,255,0.05);
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1e1e2e 0%, #2d2d44 100%);
    }
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE INITIALIZATION ====================
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'llm_model' not in st.session_state:
    st.session_state.llm_model = None
if 'llm_tokenizer' not in st.session_state:
    st.session_state.llm_tokenizer = None

# ==================== URL FEATURE EXTRACTION ====================
class URLFeatureExtractor:
    """Extract features from URL for phishing detection"""
    
    @staticmethod
    def count_occurrences(s, char):
        return s.count(char)
    
    @staticmethod
    def count_vowels(s):
        return sum(1 for char in s if char.lower() in 'aeiou')
    
    @staticmethod
    def is_ip_address(domain):
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    
    @staticmethod
    def parse_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        file = path.split('/')[-1] if '.' in path.split('/')[-1] else ''
        directory = '/'.join(path.split('/')[:-1])
        params = parsed_url.query
        return domain, directory, file, params
    
    @classmethod
    def extract_features(cls, url):
        """Extract all URL features for ML models"""
        try:
            domain, directory, file, params = cls.parse_url(url)
            
            features = {
                # URL features
                'qty_dot_url': cls.count_occurrences(url, '.'),
                'qty_hyphen_url': cls.count_occurrences(url, '-'),
                'qty_underline_url': cls.count_occurrences(url, '_'),
                'qty_slash_url': cls.count_occurrences(url, '/'),
                'qty_questionmark_url': cls.count_occurrences(url, '?'),
                'qty_equal_url': cls.count_occurrences(url, '='),
                'qty_at_url': cls.count_occurrences(url, '@'),
                'qty_and_url': cls.count_occurrences(url, '&'),
                'qty_tld_url': len(domain.split('.')[-1]) if domain else 0,
                'length_url': len(url),
                'email_in_url': int(bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', url))),
                
                # Domain features
                'qty_dot_domain': cls.count_occurrences(domain, '.'),
                'qty_hyphen_domain': cls.count_occurrences(domain, '-'),
                'qty_underline_domain': cls.count_occurrences(domain, '_'),
                'qty_vowels_domain': cls.count_vowels(domain),
                
                # Directory features
                'directory_length': len(directory),
                'qty_slash_directory': cls.count_occurrences(directory, '/'),
                
                # File features
                'file_length': len(file),
                
                # Params features
                'params_length': len(params),
                'qty_params': len(parse_qs(params)),
                'tld_present_params': int(any(tld in params for tld in ['.com', '.org', '.net', '.edu'])),
            }
            
            return features
        except Exception as e:
            st.error(f"Feature extraction error: {str(e)}")
            return None

# ==================== METADATA EXTRACTOR ====================
class MetadataExtractor:
    """Extract comprehensive metadata from URL"""
    
    @staticmethod
    def get_dns_records(domain):
        try:
            result = dns.resolver.resolve(domain, 'A')
            ips = [ip.address for ip in result]
            return ips
        except:
            return []
    
    @staticmethod
    def get_ip_info(ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            return response.json()
        except:
            return {}
    
    @staticmethod
    def get_whois_info(domain):
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            registrar = domain_info.registrar
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            return {
                'creation_date': creation_date,
                'registrar': registrar,
                'domain_age_days': (datetime.now() - creation_date).days if creation_date else None
            }
        except:
            return None
    
    @staticmethod
    def get_tls_certificate(domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issued_by = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                    issued_on = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                    expires_on = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    valid_days = (expires_on - issued_on).days
                    return {
                        'issued_by': issued_by,
                        'issued_on': issued_on,
                        'expires_on': expires_on,
                        'valid_days': valid_days,
                        'is_valid': expires_on > datetime.now()
                    }
        except:
            return None
    
    @classmethod
    def extract_all_metadata(cls, url):
        """Extract all metadata from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        metadata = {
            'url': url,
            'domain': domain,
            'protocol': parsed_url.scheme,
            'is_https': parsed_url.scheme == 'https',
            'dns_records': cls.get_dns_records(domain),
            'whois_info': cls.get_whois_info(domain),
            'tls_certificate': cls.get_tls_certificate(domain),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Get IP information
        if metadata['dns_records']:
            metadata['ip_info'] = cls.get_ip_info(metadata['dns_records'][0])
        
        return metadata

# ==================== SEO ANALYZER ====================
class SEOAnalyzer:
    """Analyze website for SEO poisoning and suspicious content"""
    
    @staticmethod
    def fetch_page_content(url, timeout=10):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            return response.text
        except:
            return None
    
    @staticmethod
    def analyze_keyword_density(soup):
        """Analyze keyword stuffing"""
        text = soup.get_text().lower()
        words = re.findall(r'\b\w+\b', text)
        if not words:
            return {'score': 0, 'suspicious': False}
        
        word_freq = {}
        for word in words:
            if len(word) > 3:
                word_freq[word] = word_freq.get(word, 0) + 1
        
        if word_freq:
            max_freq = max(word_freq.values())
            density = (max_freq / len(words)) * 100
            return {
                'score': round(density, 2),
                'suspicious': density > 5,
                'most_common': sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            }
        return {'score': 0, 'suspicious': False}
    
    @staticmethod
    def detect_hidden_content(soup):
        """Detect hidden text or links"""
        suspicious_count = 0
        
        # Check for hidden text
        for tag in soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden', re.I)):
            suspicious_count += 1
        
        # Check for text with same color as background
        for tag in soup.find_all(style=re.compile(r'color:\s*#fff|color:\s*white', re.I)):
            suspicious_count += 1
        
        return {'count': suspicious_count, 'suspicious': suspicious_count > 5}
    
    @staticmethod
    def analyze_outbound_links(soup, domain):
        """Analyze suspicious outbound links"""
        links = soup.find_all('a', href=True)
        outbound_count = 0
        suspicious_domains = []
        
        for link in links:
            href = link['href']
            if href.startswith('http') and domain not in href:
                outbound_count += 1
                link_domain = urlparse(href).netloc
                if any(suspicious in link_domain.lower() for suspicious in ['click', 'redirect', 'track', 'ad']):
                    suspicious_domains.append(link_domain)
        
        return {
            'total_outbound': outbound_count,
            'suspicious_domains': suspicious_domains,
            'suspicious': len(suspicious_domains) > 3
        }
    
    @staticmethod
    def analyze_meta_tags(soup):
        """Analyze meta tag stuffing"""
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        meta_description = soup.find('meta', attrs={'name': 'description'})
        
        keywords_count = 0
        if meta_keywords and meta_keywords.get('content'):
            keywords_count = len(meta_keywords['content'].split(','))
        
        description_length = 0
        if meta_description and meta_description.get('content'):
            description_length = len(meta_description['content'])
        
        return {
            'keywords_count': keywords_count,
            'description_length': description_length,
            'suspicious': keywords_count > 20 or description_length > 300
        }
    
    @staticmethod
    def detect_redirects(soup):
        """Detect redirect chains"""
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        return {'has_redirect': meta_refresh is not None, 'suspicious': meta_refresh is not None}
    
    @staticmethod
    def analyze_popups(soup):
        """Detect excessive popups"""
        popup_indicators = len(soup.find_all('div', class_=re.compile(r'popup|modal', re.I)))
        return {'count': popup_indicators, 'suspicious': popup_indicators > 3}
    
    @classmethod
    def analyze_website(cls, url):
        """Comprehensive SEO analysis"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        html_content = cls.fetch_page_content(url)
        if not html_content:
            return {'error': 'Failed to fetch website content'}
        
        soup = BeautifulSoup(html_content, 'html.parser')
        domain = urlparse(url).netloc
        
        analysis = {
            'keyword_density': cls.analyze_keyword_density(soup),
            'hidden_content': cls.detect_hidden_content(soup),
            'outbound_links': cls.analyze_outbound_links(soup, domain),
            'meta_tags': cls.analyze_meta_tags(soup),
            'redirects': cls.detect_redirects(soup),
            'popups': cls.analyze_popups(soup),
        }
        
        # Calculate overall suspicion score
        suspicious_count = sum([
            analysis['keyword_density']['suspicious'],
            analysis['hidden_content']['suspicious'],
            analysis['outbound_links']['suspicious'],
            analysis['meta_tags']['suspicious'],
            analysis['redirects']['suspicious'],
            analysis['popups']['suspicious']
        ])
        
        analysis['overall_score'] = (suspicious_count / 6) * 100
        analysis['verdict'] = 'SUSPICIOUS' if suspicious_count >= 3 else 'CLEAN'
        
        return analysis

# ==================== LLM ANALYZER ====================
class LLMAnalyzer:
    """Use Gemma 270M for intelligent analysis"""
    
    @staticmethod
    @st.cache_resource
    def load_model():
        """Load Gemma 270M model from HuggingFace"""
        if not HAS_TRANSFORMERS:
            return None, None
        
        try:
            model_name = "google/gemma-2-2b-it"  # Using Gemma 2B as 270M might not be available
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None
            )
            return model, tokenizer
        except:
            return None, None
    
    @staticmethod
    def analyze_with_llm(model, tokenizer, url, metadata, seo_analysis):
        """Generate intelligent analysis using LLM"""
        if model is None or tokenizer is None:
            return "LLM analysis not available. Please install transformers and torch."
        
        prompt = f"""Analyze this website for security threats:

URL: {url}
Domain Age: {metadata.get('whois_info', {}).get('domain_age_days', 'Unknown')} days
HTTPS: {metadata.get('is_https', False)}
SEO Suspicion Score: {seo_analysis.get('overall_score', 0)}%

Provide a brief security assessment in 2-3 sentences."""

        try:
            inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
            if torch.cuda.is_available():
                inputs = {k: v.cuda() for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=150,
                    temperature=0.7,
                    do_sample=True
                )
            
            response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            return response.split('\n')[-1]  # Get last line as response
        except:
            return "LLM analysis failed. Using rule-based analysis instead."

# ==================== PHISHING DETECTOR ====================
class PhishingDetector:
    """Detect phishing using ML models"""
    
    @staticmethod
    def create_dummy_model():
        """Create a simple rule-based model if ML models not available"""
        class DummyModel:
            def predict(self, features):
                # Simple rule-based prediction
                url_length = features[0][9]  # length_url
                dots = features[0][0]  # qty_dot_url
                at_signs = features[0][6]  # qty_at_url
                
                score = 0
                if url_length > 75:
                    score += 1
                if dots > 4:
                    score += 1
                if at_signs > 0:
                    score += 2
                
                return [1 if score >= 2 else 0]
        
        return DummyModel()
    
    @staticmethod
    def load_models():
        """Load ML models from pickle files"""
        models = {}
        model_names = ['xgb.pkl', 'lg.pkl', 'randomforestclassifier.pkl']
        
        for model_name in model_names:
            try:
                with open(model_name, 'rb') as f:
                    models[model_name.split('_')[0].upper()] = pickle.load(f)
            except:
                models[model_name.split('_')[0].upper()] = PhishingDetector.create_dummy_model()
        
        return models
    
    @staticmethod
    def predict_phishing(features_dict):
        """Predict if URL is phishing"""
        # Convert features to array
        feature_values = np.array(list(features_dict.values())).reshape(1, -1)
        
        # Load models
        models = PhishingDetector.load_models()
        
        predictions = {}
        for model_name, model in models.items():
            try:
                pred = model.predict(feature_values)
                predictions[model_name] = bool(pred[0])
            except:
                predictions[model_name] = False
        
        # Consensus voting
        phishing_votes = sum(predictions.values())
        is_phishing = phishing_votes >= 2
        confidence = (phishing_votes / len(predictions)) * 100
        
        return {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'individual_predictions': predictions
        }

# ==================== REPORT GENERATOR ====================
class ReportGenerator:
    """Generate downloadable PDF report"""
    
    @staticmethod
    def generate_pdf_report(url, metadata, seo_analysis, phishing_result, llm_analysis):
        """Generate comprehensive PDF report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#764ba2'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("CyberForensics Pro - Analysis Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # URL Info
        story.append(Paragraph(f"<b>Analyzed URL:</b> {url}", styles['Normal']))
        story.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Phishing Detection Results
        story.append(Paragraph("🔒 Phishing Detection Results", heading_style))
        phishing_data = [
            ['Metric', 'Value'],
            ['Is Phishing', 'YES' if phishing_result['is_phishing'] else 'NO'],
            ['Confidence', f"{phishing_result['confidence']:.1f}%"],
            ['XGBoost', 'Phishing' if phishing_result['individual_predictions'].get('XGB', False) else 'Safe'],
            ['LightGBM', 'Phishing' if phishing_result['individual_predictions'].get('LGB', False) else 'Safe'],
            ['Random Forest', 'Phishing' if phishing_result['individual_predictions'].get('RF', False) else 'Safe'],
        ]
        
        phishing_table = Table(phishing_data, colWidths=[3*inch, 3*inch])
        phishing_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(phishing_table)
        story.append(Spacer(1, 0.3*inch))
        
        # SEO Analysis
        story.append(Paragraph("🔍 SEO Poisoning Analysis", heading_style))
        seo_data = [
            ['Check', 'Status', 'Details'],
            ['Overall Verdict', seo_analysis.get('verdict', 'N/A'), f"{seo_analysis.get('overall_score', 0):.1f}% suspicious"],
            ['Keyword Density', 'Suspicious' if seo_analysis.get('keyword_density', {}).get('suspicious', False) else 'Normal', 
             f"{seo_analysis.get('keyword_density', {}).get('score', 0):.1f}%"],
            ['Hidden Content', 'Found' if seo_analysis.get('hidden_content', {}).get('suspicious', False) else 'None',
             f"{seo_analysis.get('hidden_content', {}).get('count', 0)} elements"],
            ['Suspicious Links', 'Found' if seo_analysis.get('outbound_links', {}).get('suspicious', False) else 'None',
             f"{len(seo_analysis.get('outbound_links', {}).get('suspicious_domains', []))} domains"],
            ['Meta Tag Stuffing', 'Detected' if seo_analysis.get('meta_tags', {}).get('suspicious', False) else 'Normal',
             f"{seo_analysis.get('meta_tags', {}).get('keywords_count', 0)} keywords"],
        ]
        
        seo_table = Table(seo_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        seo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#764ba2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(seo_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        story.append(Paragraph("📊 Website Metadata", heading_style))
        whois_info = metadata.get('whois_info')
        meta_data = [
            ['Property', 'Value'],
            ['Domain', metadata.get('domain', 'N/A')],
            ['Protocol', metadata.get('protocol', 'N/A').upper()],
            ['HTTPS Enabled', 'Yes' if metadata.get('is_https', False) else 'No'],
            ['Domain Age', f"{whois_info.get('domain_age_days', 'Unknown')} days" if whois_info else 'Unknown'],
            ['Registrar', whois_info.get('registrar', 'Unknown') if whois_info else 'Unknown'],
            ['IP Addresses', ', '.join(metadata.get('dns_records', ['None']))],
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))
        
        # LLM Analysis
        if llm_analysis:
            story.append(Paragraph("🤖 AI-Powered Analysis", heading_style))
            story.append(Paragraph(llm_analysis, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

# ==================== MAIN APPLICATION ====================
def main():
    # Header
    st.markdown("""
    <div class='cyber-header'>
        <h1>🔒 CyberForensics Pro</h1>
        <p>Advanced Digital Forensics Platform | URL Analysis • Phishing Detection • SEO Poisoning • Metadata Extraction</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### 🎯 Analysis Options")
        
        enable_llm = st.checkbox("Enable AI Analysis (Slower)", value=False, 
                                help="Uses Gemma LLM for intelligent analysis")
        
        st.markdown("---")
        st.markdown("### 📊 Features")
        st.markdown("""
        - 🎯 **Phishing Detection** - ML-based URL analysis
        - 🔍 **SEO Poisoning** - Detect malicious SEO tactics
        - 📈 **Metadata Extraction** - WHOIS, DNS, TLS info
        - 🤖 **AI Analysis** - LLM-powered insights
        - 📄 **PDF Reports** - Downloadable forensic reports
        """)
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
        **Version:** 1.0.0  
        **Built with:** Streamlit, XGBoost, Gemma LLM  
        **Purpose:** Digital forensics and threat intelligence
        """)
    
    # Main content
    col1, col2, col3 = st.columns([1, 3, 1])
    
    with col2:
        url_input = st.text_input(
            "🔗 Enter URL to Analyze",
            placeholder="https://example.com or example.com",
            help="Enter the complete URL or just the domain name"
        )
        
        analyze_button = st.button("🚀 Start Analysis", use_container_width=True)
    
    if analyze_button and url_input:
        # Validate URL
        if not url_input.strip():
            st.error("❌ Please enter a valid URL")
            return
        
        # Add protocol if missing
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input
        
        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # Step 1: Extract URL Features
            status_text.text("🔍 Extracting URL features...")
            progress_bar.progress(15)
            features = URLFeatureExtractor.extract_features(url_input)
            time.sleep(0.5)
            
            if features is None:
                st.error("❌ Failed to extract URL features")
                return
            
            # Step 2: Phishing Detection
            status_text.text("🎯 Running phishing detection models...")
            progress_bar.progress(30)
            phishing_result = PhishingDetector.predict_phishing(features)
            time.sleep(0.5)
            
            # Step 3: Metadata Extraction
            status_text.text("📊 Extracting metadata (DNS, WHOIS, TLS)...")
            progress_bar.progress(50)
            metadata = MetadataExtractor.extract_all_metadata(url_input)
            time.sleep(0.5)
            
            # Step 4: SEO Analysis
            status_text.text("🔍 Analyzing SEO poisoning indicators...")
            progress_bar.progress(70)
            seo_analysis = SEOAnalyzer.analyze_website(url_input)
            time.sleep(0.5)
            
            # Step 5: LLM Analysis (if enabled)
            llm_analysis = None
            if enable_llm and HAS_TRANSFORMERS:
                status_text.text("🤖 Running AI analysis...")
                progress_bar.progress(85)
                if st.session_state.llm_model is None:
                    status_text.text("🤖 Loading AI model (first time only)...")
                    st.session_state.llm_model, st.session_state.llm_tokenizer = LLMAnalyzer.load_model()
                
                if st.session_state.llm_model:
                    llm_analysis = LLMAnalyzer.analyze_with_llm(
                        st.session_state.llm_model,
                        st.session_state.llm_tokenizer,
                        url_input,
                        metadata,
                        seo_analysis
                    )
            
            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")
            time.sleep(0.5)
            progress_bar.empty()
            status_text.empty()
            
            # Store results in session state
            st.session_state.analysis_results = {
                'url': url_input,
                'features': features,
                'phishing_result': phishing_result,
                'metadata': metadata,
                'seo_analysis': seo_analysis,
                'llm_analysis': llm_analysis
            }
            st.session_state.analysis_complete = True
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            progress_bar.empty()
            status_text.empty()
            return
    
    # Display results if analysis is complete
    if st.session_state.analysis_complete and st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        st.markdown("---")
        
        # Overall Status
        st.markdown("<h2 class='section-header'>🎯 Overall Security Assessment</h2>", unsafe_allow_html=True)
        
        # Calculate overall risk score
        phishing_score = results['phishing_result']['confidence']
        seo_score = results['seo_analysis'].get('overall_score', 0)
        
        # HTTPS check
        https_score = 0 if results['metadata']['is_https'] else 30
        
        # Domain age check
        domain_age = results['metadata'].get('whois_info', {}).get('domain_age_days', 365) if results['metadata'].get('whois_info') else 365
        age_score = 20 if domain_age < 30 else 0
        
        overall_risk = (phishing_score + seo_score + https_score + age_score) / 4
        
        # Status badge
        if overall_risk < 30:
            badge_class = "safe-badge"
            status_emoji = "✅"
            status_text = "SAFE"
        elif overall_risk < 60:
            badge_class = "warning-badge"
            status_emoji = "⚠️"
            status_text = "SUSPICIOUS"
        else:
            badge_class = "danger-badge"
            status_emoji = "🚨"
            status_text = "DANGEROUS"
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown(f"""
            <div style='text-align: center; padding: 2rem;'>
                <div style='font-size: 4rem;'>{status_emoji}</div>
                <div class='status-badge {badge_class}'>{status_text}</div>
                <h3 style='color: white; margin-top: 1rem;'>Risk Score: {overall_risk:.1f}/100</h3>
            </div>
            """, unsafe_allow_html=True)
        
        # Key Metrics
        st.markdown("<h2 class='section-header'>📊 Key Metrics</h2>", unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class='metric-card'>
                <div style='color: #a0a0a0; font-size: 0.9rem; font-weight: 500;'>PHISHING RISK</div>
                <div style='color: white; font-size: 2rem; font-weight: 700;'>{phishing_score:.1f}%</div>
                <div style='color: {"#ef4444" if phishing_score > 60 else "#10b981"}; font-size: 0.9rem;'>
                    {results['phishing_result']['is_phishing'] and "⚠️ Likely Phishing" or "✅ Safe"}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class='metric-card'>
                <div style='color: #a0a0a0; font-size: 0.9rem; font-weight: 500;'>SEO POISONING</div>
                <div style='color: white; font-size: 2rem; font-weight: 700;'>{seo_score:.1f}%</div>
                <div style='color: {"#ef4444" if seo_score > 50 else "#10b981"}; font-size: 0.9rem;'>
                    {results['seo_analysis'].get('verdict', 'N/A')}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            domain_age_days = results['metadata'].get('whois_info', {}).get('domain_age_days') if results['metadata'].get('whois_info') else None
            age_display = f"{domain_age_days}" if domain_age_days else "Unknown"
            age_color = "#ef4444" if domain_age_days and domain_age_days < 30 else "#10b981"
            
            st.markdown(f"""
            <div class='metric-card'>
                <div style='color: #a0a0a0; font-size: 0.9rem; font-weight: 500;'>DOMAIN AGE</div>
                <div style='color: white; font-size: 2rem; font-weight: 700;'>{age_display}</div>
                <div style='color: {age_color}; font-size: 0.9rem;'>
                    {"⚠️ Very New" if domain_age_days and domain_age_days < 30 else "✅ Established" if domain_age_days else "❓ Unknown"}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            https_status = "✅ Secure" if results['metadata']['is_https'] else "⚠️ Not Secure"
            https_color = "#10b981" if results['metadata']['is_https'] else "#ef4444"
            
            st.markdown(f"""
            <div class='metric-card'>
                <div style='color: #a0a0a0; font-size: 0.9rem; font-weight: 500;'>PROTOCOL</div>
                <div style='color: white; font-size: 2rem; font-weight: 700;'>{results['metadata']['protocol'].upper()}</div>
                <div style='color: {https_color}; font-size: 0.9rem;'>{https_status}</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Detailed Analysis Sections
        st.markdown("---")
        
        # Phishing Detection Details
        with st.expander("🎯 Phishing Detection Details", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Model Predictions")
                for model, prediction in results['phishing_result']['individual_predictions'].items():
                    status = "🚨 Phishing" if prediction else "✅ Safe"
                    color = "#ef4444" if prediction else "#10b981"
                    st.markdown(f"**{model}:** <span style='color: {color};'>{status}</span>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("#### Confidence Score")
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=results['phishing_result']['confidence'],
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "#667eea"},
                        'steps': [
                            {'range': [0, 33], 'color': "#10b981"},
                            {'range': [33, 66], 'color': "#f59e0b"},
                            {'range': [66, 100], 'color': "#ef4444"}
                        ],
                        'threshold': {
                            'line': {'color': "white", 'width': 4},
                            'thickness': 0.75,
                            'value': results['phishing_result']['confidence']
                        }
                    }
                ))
                fig.update_layout(
                    height=250,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': 'white'}
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # SEO Analysis Details
        with st.expander("🔍 SEO Poisoning Analysis", expanded=True):
            st.markdown(f"**Overall Verdict:** <span style='color: {'#ef4444' if results['seo_analysis'].get('verdict') == 'SUSPICIOUS' else '#10b981'};'>{results['seo_analysis'].get('verdict', 'N/A')}</span>", unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Keyword Density")
                kd = results['seo_analysis'].get('keyword_density', {})
                st.write(f"Score: {kd.get('score', 0):.2f}%")
                st.write(f"Status: {'⚠️ Suspicious' if kd.get('suspicious', False) else '✅ Normal'}")
                
                st.markdown("#### Hidden Content")
                hc = results['seo_analysis'].get('hidden_content', {})
                st.write(f"Count: {hc.get('count', 0)}")
                st.write(f"Status: {'⚠️ Suspicious' if hc.get('suspicious', False) else '✅ Normal'}")
                
                st.markdown("#### Meta Tags")
                mt = results['seo_analysis'].get('meta_tags', {})
                st.write(f"Keywords: {mt.get('keywords_count', 0)}")
                st.write(f"Status: {'⚠️ Stuffed' if mt.get('suspicious', False) else '✅ Normal'}")
            
            with col2:
                st.markdown("#### Outbound Links")
                ol = results['seo_analysis'].get('outbound_links', {})
                st.write(f"Total: {ol.get('total_outbound', 0)}")
                st.write(f"Suspicious: {len(ol.get('suspicious_domains', []))}")
                st.write(f"Status: {'⚠️ Suspicious' if ol.get('suspicious', False) else '✅ Normal'}")
                
                st.markdown("#### Redirects")
                rd = results['seo_analysis'].get('redirects', {})
                st.write(f"Status: {'⚠️ Detected' if rd.get('has_redirect', False) else '✅ None'}")
                
                st.markdown("#### Popups")
                pp = results['seo_analysis'].get('popups', {})
                st.write(f"Count: {pp.get('count', 0)}")
                st.write(f"Status: {'⚠️ Excessive' if pp.get('suspicious', False) else '✅ Normal'}")
            
            # SEO Score Chart
            seo_scores = {
                'Keyword Density': kd.get('score', 0),
                'Hidden Content': hc.get('count', 0) * 10,
                'Suspicious Links': len(ol.get('suspicious_domains', [])) * 15,
                'Meta Stuffing': mt.get('keywords_count', 0) * 2,
                'Redirects': 50 if rd.get('has_redirect', False) else 0,
                'Popups': pp.get('count', 0) * 10
            }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(seo_scores.keys()),
                    y=list(seo_scores.values()),
                    marker_color='#667eea'
                )
            ])
            fig.update_layout(
                title='SEO Risk Factors',
                yaxis_title='Risk Score',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': 'white'},
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Metadata Details
        with st.expander("📊 Website Metadata", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Domain Information")
                st.write(f"**Domain:** {results['metadata']['domain']}")
                st.write(f"**Protocol:** {results['metadata']['protocol'].upper()}")
                st.write(f"**HTTPS:** {'✅ Yes' if results['metadata']['is_https'] else '❌ No'}")
                
                if results['metadata'].get('whois_info'):
                    wi = results['metadata']['whois_info']
                    st.markdown("#### WHOIS Information")
                    st.write(f"**Registrar:** {wi.get('registrar', 'Unknown')}")
                    if wi.get('creation_date'):
                        st.write(f"**Created:** {wi['creation_date'].strftime('%Y-%m-%d')}")
                    st.write(f"**Age:** {wi.get('domain_age_days', 'Unknown')} days")
            
            with col2:
                st.markdown("#### DNS Records")
                dns_records = results['metadata'].get('dns_records', [])
                if dns_records:
                    for ip in dns_records[:3]:
                        st.write(f"• {ip}")
                else:
                    st.write("No DNS records found")
                
                if results['metadata'].get('ip_info'):
                    ip_info = results['metadata']['ip_info']
                    st.markdown("#### IP Information")
                    st.write(f"**Country:** {ip_info.get('country', 'Unknown')}")
                    st.write(f"**City:** {ip_info.get('city', 'Unknown')}")
                    st.write(f"**Organization:** {ip_info.get('org', 'Unknown')}")
                
                if results['metadata'].get('tls_certificate'):
                    tls = results['metadata']['tls_certificate']
                    st.markdown("#### TLS Certificate")
                    st.write(f"**Issued By:** {tls.get('issued_by', 'Unknown')}")
                    st.write(f"**Valid:** {'✅ Yes' if tls.get('is_valid', False) else '❌ Expired'}")
        
        # URL Features
        with st.expander("🔢 Extracted URL Features"):
            df_features = pd.DataFrame([results['features']])
            st.dataframe(df_features, use_container_width=True)
        
        # LLM Analysis
        if results.get('llm_analysis'):
            with st.expander("🤖 AI-Powered Analysis"):
                st.markdown(f"<div class='info-text'>{results['llm_analysis']}</div>", unsafe_allow_html=True)
        
        # Download Report
        st.markdown("---")
        st.markdown("<h2 class='section-header'>📥 Download Report</h2>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("📄 Generate PDF Report", use_container_width=True):
                with st.spinner("Generating PDF report..."):
                    pdf_buffer = ReportGenerator.generate_pdf_report(
                        results['url'],
                        results['metadata'],
                        results['seo_analysis'],
                        results['phishing_result'],
                        results.get('llm_analysis')
                    )
                    
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_buffer,
                        file_name=f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                    st.success("✅ Report generated successfully!")
            
            # JSON Export
            if st.button("📊 Export as JSON", use_container_width=True):
                # Prepare JSON-serializable data
                export_data = {
                    'url': results['url'],
                    'timestamp': datetime.now().isoformat(),
                    'risk_score': float(overall_risk),
                    'phishing_detection': {
                        'is_phishing': results['phishing_result']['is_phishing'],
                        'confidence': float(results['phishing_result']['confidence']),
                        'predictions': results['phishing_result']['individual_predictions']
                    },
                    'seo_analysis': {
                        'verdict': results['seo_analysis'].get('verdict'),
                        'score': float(results['seo_analysis'].get('overall_score', 0))
                    },
                    'metadata': {
                        'domain': results['metadata']['domain'],
                        'protocol': results['metadata']['protocol'],
                        'is_https': results['metadata']['is_https'],
                        'dns_records': results['metadata'].get('dns_records', [])
                    }
                }
                
                json_str = json.dumps(export_data, indent=2)
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_str,
                    file_name=f"forensics_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )

if __name__ == "__main__":
    main()