#!/usr/bin/env python3
import sys
import json
import requests
import re
import time
from urllib.parse import quote

def fetch_webarchive(domain):
    """Fetch subdomains from Web Archive with improved error handling"""
    subdomains = set()
    
    endpoints = [
        "http://web.archive.org/cdx/search/cdx",
        "https://web.archive.org/cdx/search/cdx"
    ]
    
    params = {
        'url': f'*.{domain}/*',
        'output': 'json',
        'collapse': 'urlkey',
        'limit': 5000,
        'fl': 'original'
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    for endpoint in endpoints:
        try:
            response = requests.get(
                endpoint,
                params=params,
                headers=headers,
                timeout=45,
                verify=False  
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data and len(data) > 1:
                        for row in data[1:]:
                            if row and len(row) > 0:
                                url = row[0].lower()
                                # Extract domain from URL
                                pattern = r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(domain) + ')'
                                matches = re.findall(pattern, url)
                                for match in matches:
                                    if '*' not in match and not match.startswith('www.archive.org'):
                                        subdomains.add(match)
                except json.JSONDecodeError:
                
                    lines = response.text.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) > 2:
                            url = parts[2].lower()
                            pattern = r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(domain) + ')'
                            matches = re.findall(pattern, url)
                            for match in matches:
                                if '*' not in match:
                                    subdomains.add(match)
                
                if subdomains:
                    break
                    
        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            continue
    
    if not subdomains:
        try:
            timemap_url = f"https://web.archive.org/web/timemap/json?url={domain}&matchType=domain&output=json"
            response = requests.get(timemap_url, timeout=30, headers=headers)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data[1:]:  # Skip header
                        if len(entry) > 2:
                            url = entry[2].lower()
                            pattern = r'([a-zA-Z0-9._-]+\.' + re.escape(domain) + ')'
                            matches = re.findall(pattern, url)
                            for match in matches:
                                subdomains.add(match)
                except:
                    pass
        except:
            pass
    
    return sorted(subdomains)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(0)
    
    domain = sys.argv[1].lower()
    try:
        for subdomain in fetch_webarchive(domain):
            print(subdomain)
    except:
        sys.exit(0)
