#!/usr/bin/env python3
import sys
import json
import requests
import ssl
import urllib3
from urllib.parse import quote


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_crtsh(domain):
    """Fetch subdomains from crt.sh with improved error handling"""
    subdomains = set()
    
    try:
        
        endpoints = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q={quote('%.' + domain)}&output=json",
            f"https://crt.sh/?q=.{domain}&output=json"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        for url in endpoints:
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=30,
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for entry in data:
                                if 'name_value' in entry:
                                    names = str(entry['name_value']).strip()
                                    for name in names.split('\n'):
                                        name = name.strip()
                                        if name:
                                            name = name.lower()
                                            if '*' in name:
                                                name = name.replace('*.', '')
                                            if name.endswith(f'.{domain}'):
                                                subdomains.add(name)
                                            elif name == domain:
                                                subdomains.add(name)
                    
                    except json.JSONDecodeError:
                        
                        import re
                        pattern = r'[a-zA-Z0-9*.-]+\.' + domain.replace('.', '\\.')
                        matches = re.findall(pattern, response.text)
                        for match in matches:
                            if '*' not in match:
                                subdomains.add(match.lower())
                    
                    
                    if subdomains:
                        break
                        
            except requests.exceptions.RequestException:
                continue
        
        
        if not subdomains:
            try:
                url = f"https://crt.sh/?q={quote('%.' + domain)}"
                response = requests.get(url, headers=headers, timeout=30, verify=False)
                
                if response.status_code == 200:
                    import re
                    
                    pattern = r'<TD>([a-zA-Z0-9*.-]+\.' + domain.replace('.', '\\.') + ')</TD>'
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if '*' not in match:
                            subdomains.add(match.lower())
                    
                    
                    pattern2 = r'"name_value":"([^"]+)"'
                    matches2 = re.findall(pattern2, response.text)
                    for match in matches2:
                        for name in match.split('\\n'):
                            name = name.strip().lower()
                            if name and '*' not in name and f'.{domain}' in name:
                                subdomains.add(name)
            except:
                pass
    
    except Exception as e:
        
        try:
            base_domain = '.'.join(domain.split('.')[-2:])
            if base_domain != domain:
                
                return fetch_crtsh(base_domain)
        except:
            pass
    
    return subdomains

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(0)
    
    domain = sys.argv[1].lower().strip()
    results = fetch_crtsh(domain)
    
    for subdomain in sorted(results):
        print(subdomain)
