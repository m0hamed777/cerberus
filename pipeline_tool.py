#!/usr/bin/env python3
"""
Cerberus: Gateway Guardian Recon Pipeline Tool
Version: 1.0.0

A polished CLI for 403-focused reconnaissance with these improvements:
1) argparse-based subcommands with clear help
2) Colorized output via colorama
3) ASCII banner + version at startup
4) Output directory support with timestamped files
5) Progress indicators and clean headers
6) Built-in sample mode for testing
"""
import argparse
import subprocess
import sys
import socket
import random
import string
import os
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init as colorama_init

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
print(Fore.CYAN + BANNER)
print(Fore.YELLOW + "Cerberus v1.0.0 - Gateway Guardian Recon Pipeline Tool\n")

# Default threads
DEFAULT_THREADS = 50

# Utility to run shell commands
def run(cmd):
    print(Fore.BLUE + f"$ {cmd}")
    subprocess.run(cmd, shell=True, check=True)

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

# Ensure output directory
def prepare_output(path: str) -> Path:
    outdir = Path(path)
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

# Subcommand implementations

def enum_subdomains(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subs_all.txt')
    print(Fore.GREEN + f"[+] Enumerating subdomains for {args.domain}...")
    cmd = f"subfinder -d {args.domain} -silent -o {outfile}"
    run(cmd)
    print(Fore.GREEN + f"[✓] Subdomains saved to {outfile}\n")


def filter_wildcard(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subs_filtered.txt')
    print(Fore.GREEN + f"[+] Filtering wildcards on {args.domain}...\n")
    cmd = f"./wild_batch_scanner.sh {args.domain} {args.wordlist} > {outfile}"
    run(cmd)
    print(Fore.GREEN + f"[✓] Filtered subs saved to {outfile}\n")


def subscan(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'subsubs.txt')
    print(Fore.GREEN + f"[+] Scanning sub-subdomains from {args.subs_file}...\n")
    cmd = (
        f"python3 multi_subdomain_scanner.py -S {args.subs_file} "
        f"-W {args.wordlist_dir} -t {args.threads} > {outfile}"
    )
    run(cmd)
    print(Fore.GREEN + f"[✓] Sub-subdomains saved to {outfile}\n")


def wordscan(args):
    outdir = prepare_output(args.output_dir)
    print(Fore.GREEN + f"[+] Wordlist scan on {args.subdomain}...\n")
    p = subprocess.Popen(
        ['python3', 'wildcard_wordlist_scanner.py'], stdin=subprocess.PIPE, text=True
    )
    p.communicate(f"{args.subdomain}\n{args.wordlist_dir}\n")
    print(Fore.GREEN + "[✓] Wordlist scan complete.\n")


def identify_403(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'endpoints_403.txt')
    print(Fore.GREEN + f"[+] Identifying 403 endpoints on {args.subdomain}...\n")
    cmd = f"python3 bypass_403_scan.py {args.subdomain} {args.wordlist_dir} > {outfile}"
    run(cmd)
    print(Fore.GREEN + f"[✓] Endpoints list saved to {outfile}\n")


def bypass_test(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'bypass_results.txt')
    print(Fore.GREEN + "[+] Testing bypass/CORS on 403 endpoints...\n")
    cmd = f"python3 403_bypass_test.py {args.endpoints_file} > {outfile}"
    run(cmd)
    print(Fore.GREEN + f"[✓] Bypass results saved to {outfile}\n")


def admin_fuzz(args):
    outdir = prepare_output(args.output_dir)
    outfile = outdir / (args.output or 'admin_fuzz_results.txt')
    print(Fore.GREEN + f"[+] Fuzzing admin paths on {args.subdomain}...\n")
    cmd = f"python3 admin_fuzzer.py -s {args.subdomain} -w {args.wordlist} > {outfile}"
    run(cmd)
    print(Fore.GREEN + f"[✓] Admin fuzz results saved to {outfile}\n")

# Main CLI

def main():
    parser = argparse.ArgumentParser(
        description="Cerberus: Gateway Guardian Recon Pipeline Tool"
    )
    parser.add_argument('--output-dir', '-O', default='outputs', help='Directory for all output files')
    parser.add_argument('--version', action='version', version='Cerberus 1.0.0')
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
    p.add_argument('subdomain', help='Single subdomain')
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
    p.add_argument('subdomain', help='Single subdomain')
    p.add_argument('wordlist', help='Wordlist (txt) of admin paths')
    p.add_argument('-o', '--output', help='Filename for admin fuzz results')
    p.set_defaults(func=admin_fuzz)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == '__main__':
    main()

