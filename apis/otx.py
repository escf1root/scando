#!/usr/bin/env python3
import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor

def fetch_otx(domain):
    """Fetch from AlienVault OTX"""
    subdomains = set()
    
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns"
        response = requests.get(url, timeout=25, headers={
            'X-OTX-API-KEY': '',
            'User-Agent': 'Scando/3.0'
        })
        
        if response.status_code == 200:
            data = response.json()
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname', '').lower().strip()
                if hostname and hostname.endswith('.' + domain):
                    subdomains.add(hostname)
    
    except Exception:
        pass
    
    return subdomains

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(0)
    
    domain = sys.argv[1].lower()
    results = fetch_otx(domain)
    
    for subdomain in sorted(results):
        print(subdomain)
