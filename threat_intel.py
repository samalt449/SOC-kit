import os
import hashlib
import requests
from flask import Blueprint, request, render_template
from dotenv import load_dotenv

load_dotenv()

# === Blueprint ===
threat_intel_bp = Blueprint('threat_intel', __name__, template_folder='templates')

# === API KEYS ===
VT_API_KEY = ("1b2ce95d811b8e2005ed8f8817fd3b3c1716d611dd0e64aeb4bff63f32c5081b")
OTX_API_KEY = ("OTX_API_KE")
ABUSEIPDB_API_KEY = ("131e1c7859ba8b48f1cc0b81c2eaa661cc96e4c062b25a3c51560cb74b87b5475aa6353733ba8c0e")
DEEPSEEK_API_KEY = ("sk-9afb67a5c64d4a668c6f15fd13af704d")
DEEPSEEK_API_BASE = ("https://api.deepseek.com/v1")

# === Risk Mapping ===
def map_risk(level):
    level = str(level).lower()
    if level in ['malicious', 'high', 'critical', 'bad', 'blacklist']:
        return 'High'
    elif level in ['suspicious', 'medium', 'unknown']:
        return 'Medium'
    else:
        return 'Low'

# === Threat Intelligence APIs ===

def get_virustotal(query, qtype):
    headers = {"x-apikey": VT_API_KEY}
    if qtype == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    elif qtype == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{query}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{query}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        risk = 'Low'
        if malicious >= 5:
            risk = 'High'
        elif suspicious > 0 or malicious > 0:
            risk = 'Medium'
        return {
            "source": "VirusTotal",
            "status": f"{malicious} malicious, {suspicious} suspicious out of {total} vendors",
            "risk": risk,
            "report_url": f"https://www.virustotal.com/gui/search/{query}"
        }
    return {"source": "VirusTotal", "status": "Error fetching data", "risk": "Medium", "report_url": ""}

def get_alienvault(query):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        risk = 'High' if pulses >= 5 else 'Medium' if pulses > 0 else 'Low'
        return {
            "source": "AlienVault OTX",
            "status": f"Seen in {pulses} pulses",
            "risk": risk,
            "report_url": f"https://otx.alienvault.com/indicator/ip/{query}"
        }
    return {"source": "AlienVault OTX", "status": "No data", "risk": "Low", "report_url": ""}

def get_greynoise(query):
    response = requests.get(f"https://api.greynoise.io/v3/community/{query}")
    if response.status_code == 200:
        data = response.json()
        classification = data.get("classification", "unknown")
        risk = map_risk(classification)
        return {
            "source": "GreyNoise",
            "status": f"Classification: {classification}",
            "risk": risk,
            "report_url": f"https://viz.greynoise.io/ip/{query}"
        }
    return {"source": "GreyNoise", "status": "Not found", "risk": "Low", "report_url": ""}

def get_abuseipdb(query):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={query}&maxAgeInDays=90"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        score = data['data'].get("abuseConfidenceScore", 0)
        risk = 'High' if score >= 70 else 'Medium' if score >= 30 else 'Low'
        return {
            "source": "AbuseIPDB",
            "status": f"Abuse Confidence Score: {score}",
            "risk": risk,
            "report_url": f"https://www.abuseipdb.com/check/{query}"
        }
    return {"source": "AbuseIPDB", "status": "No data", "risk": "Low", "report_url": ""}

# === DeepSeek AI Summary ===
def generate_ai_summary(summaries):
    input_text = "\n".join([f"{s['source']}: {s['status']} (Risk: {s['risk']})" for s in summaries])
    prompt = f"""You are a cybersecurity threat analyst. Given the following threat intelligence summaries, assess the risk and provide a recommendation:

{input_text}

Please include if the asset should be blocked, monitored, or is safe. Explain briefly why.
"""

    try:
        response = requests.post(
            f"{DEEPSEEK_API_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity threat analyst."},
                    {"role": "user", "content": prompt}
                ]
            }
        )
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        elif response.status_code == 402:
    	    return "DeepSeek AI: Insufficient balance or quota. Please check your API usage or upgrade your plan."
        else:
            return f"AI analysis error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"AI analysis exception: {str(e)}"

# === Analyze Query ===
def analyze_query(query, qtype):
    summaries = []
    if qtype == "file":
        content = query.read()
        query = hashlib.sha256(content).hexdigest()
        qtype = "hash"

    if qtype == "auto":
        if '.' in query and all(part.isdigit() for part in query.split('.') if part):
            qtype = "ip"
        elif '.' in query:
            qtype = "domain"
        elif len(query) >= 64:
            qtype = "hash"
        else:
            qtype = "domain"

    if qtype in ['ip', 'domain', 'hash']:
        summaries.append(get_virustotal(query, qtype))
        if qtype == "ip":
            summaries.append(get_abuseipdb(query))
            summaries.append(get_alienvault(query))
            summaries.append(get_greynoise(query))
        elif qtype == "domain":
            summaries.append(get_alienvault(query))
        elif qtype == "hash":
            summaries.append(get_alienvault(query))

    ai_summary = generate_ai_summary(summaries)
    return summaries, ai_summary

# === Route ===
@threat_intel_bp.route('/threat-intel', methods=['GET', 'POST'])
def threat_intel():
    query = ''
    selected_type = 'auto'
    summaries = []
    error_message = None
    ai_summary = ''

    if request.method == 'POST':
        selected_type = request.form.get('query_type')
        if selected_type == 'file':
            file = request.files.get('file')
            if file:
                summaries, ai_summary = analyze_query(file, 'file')
            else:
                error_message = "No file uploaded."
        else:
            query = request.form.get('query')
            if query:
                summaries, ai_summary = analyze_query(query.strip(), selected_type)
            else:
                error_message = "No query provided."

    return render_template('threat_intel.html',
                           summaries=summaries,
                           error_message=error_message,
                           query=query,
                           selected_type=selected_type,
                           ai_summary=ai_summary)
