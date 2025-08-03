from flask import Flask, request, jsonify
import ssl
import socket
from datetime import datetime
import google.generativeai as genai
import os
from flask_cors import CORS
import logging
import re
import requests
import traceback
import whois
import base64

# === CONFIG ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)

# === SETUP ===
app = Flask(__name__)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === UTILS ===
def is_valid_hostname(hostname):
    return re.match(r'^[a-zA-Z0-9.-]+$', hostname) is not None

def get_certificate_info(hostname):
    context = ssl.create_default_context()
    try:
        logger.info(f"📡 Connecting to {hostname}:443 for SSL cert")
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        raise Exception(f"Could not retrieve SSL certificate: {e}")

def verify_certificate(cert):
    result = {}
    try:
        not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert.get('notBefore', ''), '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        result['valid'] = not_before <= now <= not_after
        result['valid_from'] = cert.get('notBefore', 'Unknown')
        result['valid_until'] = cert.get('notAfter', 'Unknown')
    except Exception as e:
        result['valid'] = False
        result['valid_from'] = 'Invalid date'
        result['valid_until'] = 'Invalid date'

    issuer_info = {k: v for item in cert.get('issuer', []) for k, v in item}
    subject_info = {k: v for item in cert.get('subject', []) for k, v in item}

    result['issuer'] = issuer_info.get('organizationName', 'Unknown')
    result['common_name'] = subject_info.get('commonName', 'Unknown')

    return result

def generate_feedback_with_gemini(cert_data):
    domain = cert_data.get("common_name", "").lower()
    suspicious_keywords = ['paypal', 'verify', 'secure', 'login', 'account', 'update']

    prompt = (
        f"Analyze this SSL certificate:\n\n"
        f"Issuer: {cert_data['issuer']}\n"
        f"Common Name (Domain): {cert_data['common_name']}\n"
        f"Valid From: {cert_data['valid_from']}\n"
        f"Valid Until: {cert_data['valid_until']}\n"
        f"Validity: {'Valid' if cert_data['valid'] else 'Invalid'}\n\n"
    )

    if any(keyword in domain for keyword in suspicious_keywords):
        prompt += "This domain may be suspicious. Check for phishing risk.\n"

    prompt += "Limit response to under 150 words."

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception:
        return "AI feedback unavailable due to internal error."

def check_url_with_google_safe_browsing(url_to_check):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "ecotrust", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()
        return {"safe": not bool(result.get("matches")), "details": result.get("matches")}
    except Exception:
        return {"safe": None, "error": "Safe Browsing check failed"}

def get_whois_info(hostname):
    try:
        domain_info = whois.whois(hostname)
        return {
            "domain_name": domain_info.domain_name,
            "registrar": domain_info.registrar,
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "updated_date": str(domain_info.updated_date)
        }
    except Exception:
        return {"error": "WHOIS lookup failed."}

def get_virustotal_report(hostname):
    try:
        url_id = base64.urlsafe_b64encode(f"https://{hostname}".encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "raw": stats
            }
        return {"error": "VirusTotal API error"}
    except Exception:
        return {"error": "VirusTotal check failed."}

def calculate_risk(cert_data, google_check, feedback, virustotal_info, whois_info):
    score = 0
    domain = cert_data.get("common_name", "").lower()
    if not cert_data.get("valid"):
        score += 2

    suspicious_keywords = ['paypal', 'verify', 'secure', 'login', 'account', 'update']
    if any(word in domain for word in suspicious_keywords):
        score += 2

    if any(word in feedback.lower() for word in ['phishing', 'suspicious', 'malicious']):
        score += 3

    if google_check.get("safe") is False:
        score += 3

    if isinstance(virustotal_info, dict):
        score += virustotal_info.get("malicious", 0) * 2
        score += virustotal_info.get("suspicious", 0)

    try:
        creation = whois_info.get("creation_date", "")
        if creation and "error" not in creation:
            creation_date = datetime.strptime(creation[:10], "%Y-%m-%d")
            if (datetime.utcnow() - creation_date).days < 180:
                score += 2
    except:
        pass

    if score >= 7:
        return "High Risk"
    elif score >= 3:
        return "Medium Risk"
    return "Low Risk"

# === ROUTE ===
@app.route('/api/check-ssl', methods=['POST'])
def check_ssl():
    try:
        data = request.get_json()
        hostname = data.get('hostname', '').strip().rstrip('/')
        if not hostname or not is_valid_hostname(hostname):
            return jsonify({"error": "Invalid hostname."}), 400

        cert = get_certificate_info(hostname)
        cert_data = verify_certificate(cert)
        feedback = generate_feedback_with_gemini(cert_data)
        google_result = check_url_with_google_safe_browsing(f"https://{hostname}")
        whois_result = get_whois_info(hostname)
        vt_result = get_virustotal_report(hostname)

        risk = calculate_risk(cert_data, google_result, feedback, vt_result, whois_result)

        return jsonify({
            "hostname": hostname,
            "certificate": cert_data,
            "feedback": feedback,
            "google_safe_browsing": google_result,
            "whois_info": whois_result,
            "virustotal_info": vt_result,
            "risk_level": risk
        })
    except Exception as e:
        logger.error(f"❌ Unexpected error:\n{traceback.format_exc()}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500

# === MAIN ===
if __name__ == '__main__':
    app.run(debug=True, port=5000)
