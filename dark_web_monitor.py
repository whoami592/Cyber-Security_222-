#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dark Web Monitor (Scraper)
Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer

Defensive threat-intelligence tool. Fetches pages through Tor and watches for
your keywords (brand, domains, employee emails, product names) and for leaked
credential patterns, then alerts and stores findings in SQLite + JSON.

Use ONLY for lawful monitoring of your own organisation's exposure or with
proper authorisation. Do not use it to access illegal content.

Setup:
    pip install "requests[socks]" beautifulsoup4
    Start Tor (service on 127.0.0.1:9050, or Tor Browser on 127.0.0.1:9150)

Usage:
    python dark_web_monitor.py -t targets.txt -k keywords.txt --once
    python dark_web_monitor.py -t targets.txt -k keywords.txt -i 3600 --depth 1
"""

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit('[!] Missing deps. Run: pip install "requests[socks]" beautifulsoup4')

BANNER = r"""
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡽⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⢋⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⢾⣛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠟⣿⢸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠠⠤⢤⣤⣤⣴⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣄⣿⣿⣾⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⢹⣿⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠿⠟⠒⠛⠉⠉⠉⠉⠉⠉⠉⠙⠛⠛⠻⠿⢿⣶⣤⣄⣀⠀⠀⠘⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣿⣿⠀⢀⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠿⣶⣤⣿⣿⣿⣿⣟⢿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣧⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣴⣶⣾⡿⠿⠿⠿⢿⣿⣷⣶⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡿⢿⣿⡿⠿⠛⣿⡿⠀⠀⢀⣠⣴⣾⣿⡟⠋⠉⠀⠀⠈⢧⡀⣷⣄⡂⠙⢧⡁⡝⢿⣿⣿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣧⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣦⡀⠀⢀⡴⢻⣿⣴⣾⡿⣟⣉⣼⣟⠤⠤⠖⠒⠒⠒⠒⠻⢏⡛⢬⡙⠛⠳⢄⠀⠳⣍⡻⣿⣿⣿⠿⣿⣷⣶⣤⣄⣸⣿⣿⣿⣿⡏⢧⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⢸⢹⠉⠀⢷⡏⢰⡟⠢⡄⢰⣶⣶⣿⣿⣿⣶⡖⠉⠢⢝⡂⠀⠀⠙⠢⢄⣙⣺⣿⣿⣷⣶⢾⡟⢻⣿⣿⣿⣿⣿⣿⠁⢈⡷⣄⢀⣀⣨⠭⠟⣩⣿⣿⣿
⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⡜⣼⠀⢀⠀⣇⣿⣿⣿⡿⠟⣿⣿⣿⡿⣿⢿⣎⣳⢤⣀⠈⠙⢶⡶⠤⢤⣴⣶⣶⣷⣍⣫⡾⣡⣿⠿⣜⡇⠠⢀⡏⠀⢀⢳⡈⠑⢦⣤⣴⣾⣿⣿⣿⣿
⣿⣿⣿⣦⣄⣀⣀⣀⣠⠊⡇⡏⢠⠈⠲⢿⣿⣿⣧⡀⠀⢴⣯⣙⠷⠿⠔⠊⠁⠀⠀⠉⠙⡒⠛⠦⠤⢌⣙⠋⠛⠉⠙⠛⠛⠋⠛⣼⡇⢀⣾⡇⠀⣾⡦⠽⣶⡤⣬⣭⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⡿⠿⠟⣡⡞⠁⡟⡆⢳⡀⢆⢿⠻⡑⠞⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⡐⠀⢸⠲⣄⠀⠀⠀⠉⠓⠢⠤⣀⠀⣠⠞⣁⣴⣯⢏⡇⣰⣿⡇⠘⢾⡻⢿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⢦⢱⢹⡀⠹⣌⢾⢧⠙⠦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⠀⢸⠀⠈⡆⠀⠀⠀⠀⠀⠑⠤⣉⣙⣉⢅⡾⢃⣾⣴⢯⡇⢻⡀⢠⣙⣦⣬⣽⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣷⣶⣶⡇⢸⡘⡄⢻⣄⠙⢿⣶⢵⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢦⢘⣆⣠⠇⠀⠀⠀⠀⠀⠀⠀⠀⠰⢚⣹⢷⣿⡟⢡⣿⠁⠘⣧⡈⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣎⡇⠘⡄⠻⣷⣄⠙⠧⣄⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣼⣋⣴⡿⡼⢀⡀⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⠃⠀⢨⢦⢌⣢⣙⣷⡺⣍⡉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣯⡟⢹⣿⣧⠇⢸⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢠⠀⢳⣷⣌⡙⠻⢧⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠤⣔⣒⠦⠤⠄⠀⠀⠀⠀⠀⠀⢠⢯⣾⢈⢼⡟⠏⢠⢿⢇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢸⣦⠀⠻⡝⣿⠛⡖⣿⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣰⡞⠁⣰⢋⡞⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡼⣿⣷⣄⠹⣼⢯⣷⠘⣿⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⣿⣿⣿⣫⣴⢛⢳⣯⣞⣉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠙⣾⣮⣿⣤⣿⣞⣿⣷⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠁⢀⣿⣿⣿⣿⣾⣷⣿⡈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⢠⣿⣿⣿⣿⣷⣿⣿⣿⣆⠈⠑⠢⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠛⠁⣠⠔⠋⣿⣿⣿⣿⣿⣿⣿⣿⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠃⠐⢋⣾⣿⣿⣿⣾⣿⣿⣿⣿⡀⠀⠀⠀⠉⠒⠤⢄⣀⣀⡠⠔⠋⣀⣠⣤⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⡿⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⣀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⠉⣉⣍⣩⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣎⠉⢃⠈⣼⣿⣿⣿⣿⣿⣿⡿⠟⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣤⣄⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠹⣿⣿⣿⣿⣦⣼⢤⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠀⣀⣉⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⡀⠀⡏⠹⡟⣿⣿⢀⡎⣽⠋⢰⠁⠀⠀⠀⠀⢀⣠⡴⠿⣛⣭⡷⠿⠛⠋⠉⠁⠀⢀⡤⣺⣷⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠘⡟⣿⣆⡇⠀⢳⣷⣿⣿⢰⠏⠀⢺⣀⠤⠴⣒⣫⣽⣶⠾⠛⠉⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⡏⠀⠀⠙⢮⣙⣷⠄⢀⣿⣿⣧⠋⠤⢒⡏⡔⢛⡉⠁⢀⠉⢀⠀⠀⠀⠀⠀⠀⠀⢀⡠⣻⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⠔⢉
"""

TITLE = "DARK WEB MONITOR (SCRAPER)"
CREDIT = "Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer"

# ---------- Detection patterns ----------
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
CRED_RE = re.compile(r"([\w.+-]+@[\w-]+\.[\w.-]+)[:|;,](\S{3,64})")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")

UA = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "x": "\033[0m"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def show_banner():
    print(C["c"] + BANNER + C["x"])
    print(C["g"] + f"   {TITLE}".center(60) + C["x"])
    print(C["y"] + f"   {CREDIT}".center(60) + C["x"] + "\n")


def mask(secret):
    """Never store full leaked passwords - keep only a hint."""
    return secret[0] + "*" * (len(secret) - 1) if secret else secret


# ---------- Storage ----------
class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS pages(
            url TEXT PRIMARY KEY, hash TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, url TEXT,
            type TEXT, value TEXT, context TEXT, UNIQUE(url, type, value));
        """)

    def page_changed(self, url, digest):
        row = self.db.execute("SELECT hash FROM pages WHERE url=?", (url,)).fetchone()
        ts = now()
        if row is None:
            self.db.execute("INSERT INTO pages VALUES(?,?,?,?)", (url, digest, ts, ts))
            changed = True
        else:
            changed = row[0] != digest
            self.db.execute("UPDATE pages SET hash=?, last_seen=? WHERE url=?", (digest, ts, url))
        self.db.commit()
        return changed

    def add_finding(self, f):
        try:
            self.db.execute(
                "INSERT INTO findings(ts,url,type,value,context) VALUES(?,?,?,?,?)",
                (f["ts"], f["url"], f["type"], f["value"], f["context"]))
            self.db.commit()
            return True  # new
        except sqlite3.IntegrityError:
            return False  # already known


# ---------- Tor session ----------
def tor_session(host, port):
    s = requests.Session()
    proxy = f"socks5h://{host}:{port}"  # socks5h => DNS resolved inside Tor (needed for .onion)
    s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.5"})
    return s


def check_tor(session):
    try:
        r = session.get("https://check.torproject.org/api/ip", timeout=30)
        data = r.json()
        return bool(data.get("IsTor")), data.get("IP")
    except Exception as e:
        return False, str(e)


def renew_circuit(port, password):
    """Optional: new Tor identity (needs `pip install stem` and ControlPort enabled)."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=port) as ctl:
            ctl.authenticate(password=password or None)
            ctl.signal(Signal.NEWNYM)
        time.sleep(ctl.get_newnym_wait() if hasattr(ctl, "get_newnym_wait") else 5)
    except Exception as e:
        print(f"{C['y']}[!] Circuit renewal skipped: {e}{C['x']}")


# ---------- Scraping / analysis ----------
def fetch(session, url, timeout):
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", "text"):
            return r.text
        print(f"{C['y']}[-] {url} -> HTTP {r.status_code}{C['x']}")
    except requests.RequestException as e:
        print(f"{C['r']}[x] {url} -> {type(e).__name__}{C['x']}")
    return None


def analyse(url, html, keywords):
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style"]):
        t.decompose()
    text = soup.get_text(" ", strip=True)
    findings = []

    def add(kind, value, ctx=""):
        findings.append({"ts": now(), "url": url, "type": kind, "value": value, "context": ctx[:200]})

    low = text.lower()
    for kw in keywords:
        for m in re.finditer(re.escape(kw.lower()), low):
            s, e = max(0, m.start() - 70), min(len(text), m.end() + 70)
            add("keyword", kw, text[s:e])
            break  # one context snippet per keyword per page

    # Leaked credential pairs - only flag when the email matches a watched keyword/domain
    for em, pw in CRED_RE.findall(text):
        if any(kw.lower() in em.lower() for kw in keywords):
            add("credential_leak", f"{em}:{mask(pw)}", "email:password pattern for watched domain")

    for em in set(EMAIL_RE.findall(text)):
        if any(kw.lower() in em.lower() for kw in keywords):
            add("watched_email", em)

    for b in set(BTC_RE.findall(text)):
        add("btc_address", b)

    links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
    return findings, links, hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def crawl(session, store, seed, keywords, depth, max_pages, delay, timeout):
    host = urlparse(seed).netloc
    queue, seen, results = deque([(seed, 0)]), {seed}, []
    pages = 0
    while queue and pages < max_pages:
        url, d = queue.popleft()
        html = fetch(session, url, timeout)
        pages += 1
        if not html:
            continue
        findings, links, digest = analyse(url, html, keywords)
        changed = store.page_changed(url, digest)
        print(f"{C['g']}[+] {url}{C['x']}  (depth {d}, {'NEW/CHANGED' if changed else 'unchanged'})")
        for f in findings:
            if store.add_finding(f):
                results.append(f)
        if d < depth:
            for l in links:
                p = urlparse(l)
                if p.netloc == host and p.scheme in ("http", "https") and l not in seen:
                    seen.add(l.split("#")[0])
                    queue.append((l.split("#")[0], d + 1))
        time.sleep(delay)
    return results


# ---------- Alerts ----------
def alert(results, webhook):
    for f in results:
        color = C["r"] if f["type"] == "credential_leak" else C["y"]
        print(f"{color}[ALERT] {f['type'].upper():16} {f['value']}\n"
              f"        {f['url']}\n        ...{f['context']}...{C['x']}")
    if webhook and results:
        summary = "\n".join(f"{f['type']}: {f['value']} @ {f['url']}" for f in results[:20])
        try:  # clearnet on purpose - webhook should not go through Tor
            requests.post(webhook, json={"text": f"Dark Web Monitor: {len(results)} new finding(s)\n{summary}"}, timeout=15)
        except requests.RequestException as e:
            print(f"{C['r']}[x] Webhook failed: {e}{C['x']}")


def read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def main():
    ap = argparse.ArgumentParser(description=TITLE + " - " + CREDIT)
    ap.add_argument("-t", "--targets", required=True, help="file with .onion/http URLs (one per line)")
    ap.add_argument("-k", "--keywords", required=True, help="file with keywords/domains to watch")
    ap.add_argument("-i", "--interval", type=int, default=3600, help="seconds between cycles")
    ap.add_argument("--once", action="store_true", help="run a single cycle and exit")
    ap.add_argument("--depth", type=int, default=0, help="same-site crawl depth (default 0)")
    ap.add_argument("--max-pages", type=int, default=20, help="max pages per target")
    ap.add_argument("--delay", type=float, default=3.0, help="delay between requests (be polite)")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--tor-host", default="127.0.0.1")
    ap.add_argument("--tor-port", type=int, default=9050, help="9050 = tor service, 9150 = Tor Browser")
    ap.add_argument("--control-port", type=int, default=0, help="Tor ControlPort for circuit renewal (e.g. 9051)")
    ap.add_argument("--control-pass", default="")
    ap.add_argument("--webhook", default="", help="Slack/Discord/Teams-style webhook URL for alerts")
    ap.add_argument("--db", default="darkweb_monitor.db")
    ap.add_argument("-o", "--output", default="darkweb_report.json")
    args = ap.parse_args()

    show_banner()
    targets, keywords = read_lines(args.targets), read_lines(args.keywords)
    if not targets or not keywords:
        sys.exit("[!] Targets and keywords files must not be empty.")

    session = tor_session(args.tor_host, args.tor_port)
    ok, info = check_tor(session)
    if not ok:
        sys.exit(f"{C['r']}[!] Tor not reachable/active on {args.tor_host}:{args.tor_port} ({info}){C['x']}")
    print(f"{C['g']}[✓] Connected through Tor. Exit IP: {info}{C['x']}")
    print(f"[i] {len(targets)} target(s), {len(keywords)} keyword(s)\n")

    store, all_results = Store(args.db), []
    try:
        while True:
            print(f"{C['c']}=== Cycle started {now()} ==={C['x']}")
            cycle = []
            for t in targets:
                cycle += crawl(session, store, t, keywords, args.depth,
                               args.max_pages, args.delay, args.timeout)
            alert(cycle, args.webhook)
            all_results += cycle
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(all_results, fh, indent=2)
            print(f"{C['c']}=== Cycle done: {len(cycle)} new finding(s) | report: {args.output} ==={C['x']}\n")
            if args.once:
                break
            if args.control_port:
                renew_circuit(args.control_port, args.control_pass)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")


if __name__ == "__main__":
    main()
