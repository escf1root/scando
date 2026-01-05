#!/usr/bin/env python3
import sys
import json
import requests
import time

def fetch_urlscan(domain):
    """Fetch from URLScan.io"""
    subdomains = set()
    
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        response = requests.get(url, timeout=30, headers={
            'User-Agent': 'Scando-Enumeration-Tool/3.0'
        })
        
        if response.status_code == 200:
            data = response.json()
            
            
            for result in data.get('results', []):
                page = result.get('page', {})
                page_domain = page.get('domain', '').lower().strip()
                if page_domain and page_domain.endswith('.' + domain):
                    subdomains.add(page_domain)
            
            
            total = data.get('total', 0)
            if total > 100:
                for page_num in range(2, min(6, (total // 100) + 2)):
                    try:
                        paginated_url = f"{url}&page={page_num}"
                        resp = requests.get(paginated_url, timeout=20)
                        if resp.status_code == 200:
                            page_data = resp.json()
                            for result in page_data.get('results', []):
                                page = result.get('page', {})
                                page_domain = page.get('domain', '').lower().strip()
                                if page_domain and page_domain.endswith('.' + domain):
                                    subdomains.add(page_domain)
                    except:
                        break
    
    except Exception:
        pass
    
    return subdomains

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(0)
    
    domain = sys.argv[1].lower()
    results = fetch_urlscan(domain)
    
    for subdomain in sorted(results):
        print(subdomain)
