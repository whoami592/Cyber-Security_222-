#!/usr/bin/env python3
"""
DNS Security Monitor
====================
Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan

A defensive DNS monitoring tool that watches DNS traffic (live capture or a
PCAP file) and flags indicators of common DNS-based threats:

  * DGA-like / algorithmically generated domains (entropy + structure)
  * DNS tunneling / data exfiltration (long names, many unique subdomains,
    heavy TXT/NULL queries)
  * Queries to blocklisted domains or suspicious TLDs
  * Punycode / possible homograph domains
  * Query-rate floods from a single client
  * NXDOMAIN bursts (typical of malware hunting for its C2)
  * Fast-flux behaviour (one domain resolving to many unique IPs)

Modes
-----
  Live capture : sudo python3 dns_security_monitor.py -i eth0
  PCAP replay  : python3 dns_security_monitor.py --pcap capture.pcap
  Offline check: python3 dns_security_monitor.py --check example.com xj3k9q2vplm8.top
  Domain list  : python3 dns_security_monitor.py --domains domains.txt

Live/PCAP modes require scapy (pip install scapy). Offline modes need only
the Python standard library.

Use only on networks you own or are authorised to monitor.
"""

import argparse
import json
import math
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Banner
# --------------------------------------------------------------------------- #
BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣨⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⡏⠀⠀⠀⠀⠀⠀⣠⣾⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⡏⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠁⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⣤⣄⣤⣀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣤⡀⠀⠀⠀⠀⠀⠀⠿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡧⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣴⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣿⣿⣿⣿⣧⠉⠻⠿⠿⠿⠿⠇⠉⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠻⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣧⣼⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠘⢿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠹⢿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⣿⣿⣿⣿⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣷⣀⣻⣿⣿⣄⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⢀⡀⠀⠀⢀⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⡀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣶⣿⣿⣿⣿⡟⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⣦⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⠿⣿⣿⣿⠿⠿⠿⠿⠟⠛⠋⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "DNS SECURITY MONITOR"
AUTHOR = "Coded by Cyber Security Engineer Mr. Sabaz Ali Khan"

# --------------------------------------------------------------------------- #
#  Console colours
# --------------------------------------------------------------------------- #
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    MAG = "\033[95m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


def print_banner(use_color=True):
    col = (lambda s, c: f"{c}{s}{C.END}") if use_color else (lambda s, c: s)
    print(col(BANNER, C.CYN))
    width = max(len(TITLE), len(AUTHOR)) + 6
    line = "═" * width
    print(col(f"╔{line}╗", C.GRN))
    print(col(f"║{TITLE.center(width)}║", C.GRN))
    print(col(f"║{AUTHOR.center(width)}║", C.GRN))
    print(col(f"╚{line}╝", C.GRN))
    print()


# --------------------------------------------------------------------------- #
#  Detection configuration
# --------------------------------------------------------------------------- #
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "loan", "country", "kim", "men", "party", "review", "science", "stream",
    "download", "racing", "win", "bid", "cricket", "date", "faith", "accountant",
}

# Small built-in sample blocklist; extend with --blocklist file.
DEFAULT_BLOCKLIST = {
    "malware.testing.google.test",
    "evil.example",
    "c2.badactor.example",
}

# Well-known legitimate domains that look "random" but are not (CDNs, etc.)
ALLOWLIST_SUFFIXES = (
    "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net",
    "googleusercontent.com", "gstatic.com", "windowsupdate.com",
    "microsoft.com", "apple.com", "cdn77.org", "fastly.net", "in-addr.arpa",
    "ip6.arpa", "local", "localdomain", "arpa",
)

TUNNEL_QTYPES = {10: "NULL", 16: "TXT", 255: "ANY"}
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
               28: "AAAA", 33: "SRV", 10: "NULL", 255: "ANY"}

THRESHOLDS = {
    "entropy": 3.6,              # Shannon entropy of the main label
    "dga_min_len": 11,           # minimum label length considered for DGA
    "long_name": 100,            # total FQDN length
    "long_label": 40,            # single label length
    "unique_subs": 25,           # unique subdomains of one parent / window
    "rate_queries": 100,         # queries per window per client
    "rate_window": 10,           # seconds
    "nxdomain_burst": 20,        # NXDOMAINs per window per client
    "fastflux_ips": 8,           # unique IPs for one domain
    "tunnel_qtype_hits": 15,     # TXT/NULL/ANY queries per window per client
    "alert_cooldown": 60,        # seconds between identical alerts
}

SEVERITY_COLOR = {"LOW": C.CYN, "MEDIUM": C.YEL, "HIGH": C.RED}


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_domain(fqdn: str):
    """Return (subdomain_labels, main_label, tld). Naive public-suffix handling."""
    labels = fqdn.lower().strip(".").split(".")
    if len(labels) == 1:
        return [], labels[0], ""
    two_part_slds = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(labels) >= 3 and labels[-2] in two_part_slds and len(labels[-1]) == 2:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    return labels[:-2], labels[-2], labels[-1]


def parent_domain(fqdn: str) -> str:
    subs, main, tld = split_domain(fqdn)
    return f"{main}.{tld}" if tld else main


def is_allowlisted(fqdn: str) -> bool:
    f = fqdn.lower().strip(".")
    return any(f == s or f.endswith("." + s) for s in ALLOWLIST_SUFFIXES)


def vowel_ratio(s: str) -> float:
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(c in "aeiou" for c in letters) / len(letters)


def digit_ratio(s: str) -> float:
    return sum(c.isdigit() for c in s) / len(s) if s else 0.0


# --------------------------------------------------------------------------- #
#  Static (per-domain) analysis
# --------------------------------------------------------------------------- #
def analyze_domain(fqdn: str, blocklist=frozenset()):
    """Return a list of (severity, rule, detail) findings for a domain name."""
    findings = []
    f = fqdn.lower().strip(".")
    if not f:
        return findings

    if f in blocklist or parent_domain(f) in blocklist:
        findings.append(("HIGH", "BLOCKLIST", f"{f} is on the blocklist"))

    if is_allowlisted(f):
        return findings

    subs, main, tld = split_domain(f)
    labels = f.split(".")

    # Suspicious TLD
    if tld.split(".")[-1] in SUSPICIOUS_TLDS:
        findings.append(("LOW", "SUSPICIOUS_TLD", f"TLD .{tld} is commonly abused"))

    # Punycode / homograph
    if any(l.startswith("xn--") for l in labels):
        findings.append(("MEDIUM", "PUNYCODE",
                         "Internationalised (xn--) label - check for homograph spoofing"))

    # DGA heuristics on the registrable label
    if len(main) >= THRESHOLDS["dga_min_len"]:
        ent = shannon_entropy(main)
        vr = vowel_ratio(main)
        dr = digit_ratio(main)
        score = 0
        if ent >= THRESHOLDS["entropy"]:
            score += 1
        if vr < 0.20 or vr > 0.75:
            score += 1
        if dr > 0.30:
            score += 1
        if "-" not in main and score >= 2:
            sev = "HIGH" if score == 3 else "MEDIUM"
            findings.append((sev, "DGA_SUSPECT",
                             f"label '{main}' entropy={ent:.2f} "
                             f"vowels={vr:.0%} digits={dr:.0%}"))

    # Tunneling heuristics
    if len(f) > THRESHOLDS["long_name"]:
        findings.append(("MEDIUM", "LONG_QNAME",
                         f"FQDN length {len(f)} > {THRESHOLDS['long_name']}"))
    for l in subs:
        if len(l) > THRESHOLDS["long_label"]:
            ent = shannon_entropy(l)
            sev = "HIGH" if ent > 3.5 else "MEDIUM"
            findings.append((sev, "LONG_LABEL",
                             f"subdomain label length {len(l)}, entropy {ent:.2f} "
                             "(possible DNS tunnel / exfil)"))
            break

    return findings


# --------------------------------------------------------------------------- #
#  Stateful monitor
# --------------------------------------------------------------------------- #
class DNSMonitor:
    def __init__(self, blocklist=None, log_path=None, use_color=True, quiet=False):
        self.blocklist = set(DEFAULT_BLOCKLIST) | set(blocklist or [])
        self.log_path = log_path
        self.use_color = use_color
        self.quiet = quiet

        self.q_times = defaultdict(deque)          # src -> timestamps
        self.nx_times = defaultdict(deque)         # client -> NXDOMAIN timestamps
        self.tunnel_times = defaultdict(deque)     # src -> TXT/NULL/ANY timestamps
        self.subdomains = defaultdict(lambda: defaultdict(deque))  # parent -> sub -> ts
        self.domain_ips = defaultdict(set)         # domain -> set(IPs)
        self.last_alert = {}                       # dedupe key -> ts

        self.stats = Counter()
        self.alert_counts = Counter()
        self.top_domains = Counter()
        self.top_clients = Counter()
        self.started = time.time()

    # ---- utilities ------------------------------------------------------- #
    @staticmethod
    def _prune(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()

    def alert(self, severity, rule, src, domain, detail, now=None):
        now = now or time.time()
        key = (rule, src, parent_domain(domain) if domain else "")
        if now - self.last_alert.get(key, 0) < THRESHOLDS["alert_cooldown"]:
            return
        self.last_alert[key] = now
        self.alert_counts[rule] += 1
        self.stats["alerts"] += 1

        ts = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        record = {"time": ts, "severity": severity, "rule": rule,
                  "client": src, "domain": domain, "detail": detail}

        if not self.quiet:
            if self.use_color:
                color = SEVERITY_COLOR.get(severity, "")
                print(f"{C.DIM}{ts}{C.END} {color}{C.BLD}[{severity:<6}]{C.END} "
                      f"{C.MAG}{rule:<15}{C.END} client={src} "
                      f"domain={domain or '-'} | {detail}")
            else:
                print(f"{ts} [{severity:<6}] {rule:<15} client={src} "
                      f"domain={domain or '-'} | {detail}")

        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
            except OSError as exc:
                print(f"[!] Could not write log: {exc}", file=sys.stderr)

    # ---- event handlers -------------------------------------------------- #
    def on_query(self, src, qname, qtype, now=None):
        now = now or time.time()
        qname = qname.lower().strip(".")
        self.stats["queries"] += 1
        self.top_domains[parent_domain(qname)] += 1
        self.top_clients[src] += 1

        # Per-domain static checks
        for sev, rule, detail in analyze_domain(qname, self.blocklist):
            self.alert(sev, rule, src, qname, detail, now)

        # Query-rate flood
        dq = self.q_times[src]
        dq.append(now)
        self._prune(dq, now, THRESHOLDS["rate_window"])
        if len(dq) >= THRESHOLDS["rate_queries"]:
            self.alert("MEDIUM", "QUERY_FLOOD", src, "",
                       f"{len(dq)} queries in {THRESHOLDS['rate_window']}s", now)

        # TXT / NULL / ANY heavy usage
        if qtype in TUNNEL_QTYPES:
            tq = self.tunnel_times[src]
            tq.append(now)
            self._prune(tq, now, 60)
            if len(tq) >= THRESHOLDS["tunnel_qtype_hits"]:
                self.alert("HIGH", "TUNNEL_QTYPE", src, qname,
                           f"{len(tq)} {TUNNEL_QTYPES[qtype]} queries in 60s "
                           "(possible DNS tunnel)", now)

        # Many unique subdomains of one parent
        if not is_allowlisted(qname):
            subs, main, tld = split_domain(qname)
            if subs:
                parent = parent_domain(qname)
                sub_key = ".".join(subs)
                table = self.subdomains[parent]
                table[sub_key].append(now)
                # prune old entries
                for k in list(table.keys()):
                    self._prune(table[k], now, 60)
                    if not table[k]:
                        del table[k]
                if len(table) >= THRESHOLDS["unique_subs"]:
                    self.alert("HIGH", "MANY_SUBDOMAINS", src, parent,
                               f"{len(table)} unique subdomains in 60s "
                               "(possible exfiltration / tunneling)", now)

    def on_response(self, client, qname, rcode, ips, now=None):
        now = now or time.time()
        qname = (qname or "").lower().strip(".")
        self.stats["responses"] += 1

        if rcode == 3:  # NXDOMAIN
            self.stats["nxdomain"] += 1
            dq = self.nx_times[client]
            dq.append(now)
            self._prune(dq, now, THRESHOLDS["rate_window"])
            if len(dq) >= THRESHOLDS["nxdomain_burst"]:
                self.alert("HIGH", "NXDOMAIN_BURST", client, qname,
                           f"{len(dq)} NXDOMAIN replies in "
                           f"{THRESHOLDS['rate_window']}s (DGA / C2 hunting?)", now)

        if ips and qname and not is_allowlisted(qname):
            s = self.domain_ips[qname]
            s.update(ips)
            if len(s) >= THRESHOLDS["fastflux_ips"]:
                self.alert("HIGH", "FAST_FLUX", client, qname,
                           f"{len(s)} unique IPs observed for one domain", now)

    # ---- reporting ------------------------------------------------------- #
    def summary(self):
        elapsed = max(time.time() - self.started, 1)
        print()
        print(f"{C.BLD}{'=' * 60}{C.END}")
        print(f"{C.BLD} DNS Security Monitor - Session Summary{C.END}")
        print(f"{C.BLD}{'=' * 60}{C.END}")
        print(f" Runtime        : {elapsed:.0f}s")
        print(f" Queries        : {self.stats['queries']}")
        print(f" Responses      : {self.stats['responses']}")
        print(f" NXDOMAIN       : {self.stats['nxdomain']}")
        print(f" Alerts raised  : {self.stats['alerts']}")
        if self.alert_counts:
            print("\n Alerts by rule:")
            for rule, n in self.alert_counts.most_common():
                print(f"   {rule:<18} {n}")
        if self.top_domains:
            print("\n Top queried domains:")
            for d, n in self.top_domains.most_common(5):
                print(f"   {d:<35} {n}")
        if self.top_clients:
            print("\n Top clients:")
            for c, n in self.top_clients.most_common(5):
                print(f"   {c:<35} {n}")
        if self.log_path:
            print(f"\n Alert log      : {self.log_path}")
        print()


# --------------------------------------------------------------------------- #
#  Packet processing (scapy)
# --------------------------------------------------------------------------- #
def build_packet_handler(monitor: DNSMonitor):
    try:
        from scapy.all import DNS, DNSRR, IP, IPv6
    except ImportError:
        print("[!] scapy is required for live/PCAP mode:  pip install scapy",
              file=sys.stderr)
        sys.exit(1)

    def handler(pkt):
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        ip = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
        if ip is None or not dns.qd:
            return
        try:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
        except AttributeError:
            qname = str(dns.qd.qname).rstrip(".")
        now = float(getattr(pkt, "time", time.time()))

        if dns.qr == 0:  # query
            monitor.on_query(ip.src, qname, dns.qd.qtype, now)
        else:            # response
            ips = []
            for i in range(dns.ancount or 0):
                try:
                    rr = dns.an[i]
                except Exception:
                    break
                if getattr(rr, "type", None) in (1, 28):
                    ips.append(str(rr.rdata))
            monitor.on_response(ip.dst, qname, dns.rcode, ips, now)

    return handler


def run_live(monitor, iface, bpf, count):
    from scapy.all import sniff
    handler = build_packet_handler(monitor)
    print(f"[*] Sniffing DNS on {iface or 'default interface'} "
          f"(filter: {bpf}) - Ctrl+C to stop\n")
    try:
        sniff(iface=iface, filter=bpf, prn=handler, store=False, count=count or 0)
    except PermissionError:
        print("[!] Permission denied - run as root / Administrator.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


def run_pcap(monitor, path):
    from scapy.all import PcapReader
    handler = build_packet_handler(monitor)
    print(f"[*] Analysing PCAP: {path}\n")
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                handler(pkt)
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)


# --------------------------------------------------------------------------- #
#  Offline modes
# --------------------------------------------------------------------------- #
def run_check(monitor, domains):
    print(f"[*] Offline analysis of {len(domains)} domain(s)\n")
    for d in domains:
        d = d.strip()
        if not d or d.startswith("#"):
            continue
        findings = analyze_domain(d, monitor.blocklist)
        if not findings:
            print(f"{C.GRN if monitor.use_color else ''}[ OK ]"
                  f"{C.END if monitor.use_color else ''} {d}")
            monitor.stats["queries"] += 1
            continue
        monitor.stats["queries"] += 1
        for sev, rule, detail in findings:
            monitor.alert(sev, rule, "offline", d, detail)


def load_lines(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [l.strip().lower() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as exc:
        print(f"[!] Cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(1)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        description="DNS Security Monitor - coded by Mr. Sabaz Ali Khan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use only on networks you own or are authorised to monitor.")
    src = p.add_argument_group("input (choose one)")
    src.add_argument("-i", "--interface", help="network interface for live capture")
    src.add_argument("-r", "--pcap", help="analyse a PCAP file")
    src.add_argument("--check", nargs="+", metavar="DOMAIN",
                     help="analyse domain names offline (no scapy needed)")
    src.add_argument("--domains", metavar="FILE",
                     help="file with one domain per line to analyse offline")

    p.add_argument("--blocklist", metavar="FILE", help="extra blocklist (one domain per line)")
    p.add_argument("-l", "--log", default="dns_alerts.jsonl",
                   help="JSON-lines alert log (default: dns_alerts.jsonl; '' to disable)")
    p.add_argument("--filter", default="udp port 53 or tcp port 53",
                   help="BPF filter for live capture")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets (live)")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    p.add_argument("--no-banner", action="store_true", help="do not print the banner")
    return p.parse_args()


def main():
    args = parse_args()
    use_color = not args.no_color and sys.stdout.isatty()
    if not use_color:
        for attr in ("RED", "YEL", "GRN", "CYN", "MAG", "BLD", "DIM", "END"):
            setattr(C, attr, "")

    if not args.no_banner:
        print_banner(use_color)

    blocklist = load_lines(args.blocklist) if args.blocklist else []
    monitor = DNSMonitor(blocklist=blocklist, log_path=args.log or None,
                         use_color=use_color)

    if args.check:
        run_check(monitor, args.check)
    elif args.domains:
        run_check(monitor, load_lines(args.domains))
    elif args.pcap:
        run_pcap(monitor, args.pcap)
    elif args.interface is not None or len(sys.argv) == 1:
        run_live(monitor, args.interface, args.filter, args.count)
    else:
        print("[!] Choose an input: -i IFACE, --pcap FILE, --check DOMAIN, or --domains FILE")
        sys.exit(2)

    monitor.summary()


if __name__ == "__main__":
    main()
