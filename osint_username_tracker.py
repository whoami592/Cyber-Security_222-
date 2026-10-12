#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Username Tracker
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Checks whether a username exists across popular public platforms.
For authorized OSINT research, investigations and self-audits only.

Usage:
    python osint_username_tracker.py <username>
    python osint_username_tracker.py <username> -t 30 -o results.json
    python osint_username_tracker.py <username> --csv results.csv --found-only
    python osint_username_tracker.py -f usernames.txt

Requires: pip install requests
"""

import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] Missing dependency. Install with: pip install requests")
    sys.exit(1)

BANNER = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣶⣿⠿⢿⣿⣿⡿⣿⣿⣷⣦⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⡿⢋⣵⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⣫⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣞⣵⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⠦⡄⠀⠀⣀⣀⣤⣤⣴⢤⣤⣤⣶⣾⣿⣿⣿⣿⣿⡿⠃⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢿⣿⣿⣿⣿⣿⠿⢛⣀⣤⣤⣄⣄⣀⣻⣻⣘⣠⣤⣧⣿⣧⣤⣿⣿⣿⣿⠇⣿⠻⢜⡻⠿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⣷⣿⣿⣿⣻⣭⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢟⣩⣾⣿⣿⣿⣿⠟⣸⡇⠰⡦⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⡿⣿⣭⣛⡛⠿⣿⣿⡿⠿⠿⠿⠟⢿⣛⣹⣽⣯⣶⣿⣿⣿⣿⣿⣿⣏⠸⣟⣓⣢⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡦⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣾⣟⣿⣯⣿⣿⣿⣷⣋⣀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣿⣿⣿⣿⡏⠉⠉⠉⠉⠉⠉⠉⠛⠛⠛⠉⠉⠉⠙⠋⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⣿⣿⣿⣿⣿⣽⣯⣽⣷⡆⠀⠀⠻⠿⠓⠛⠛⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢡⣭⡹⢿⣿⠃⠀⠀⠀⠘⢯⠀⢀⣀⣀⣀⢠⣤⣬⣧⣿⣷⣮⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣷⣄⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣯⣯⣩⣽⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⢟⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢏⣵⣾⣿⢣⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣛⣵⣿⣿⠿⣣⣾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣟⣛⣛⣛⣯⣿⣶⣿⣿⠿⣋⣽⣾⣿⣿⣿⠀⢰⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠋⣠⣠⣿⣝⢻⣿⣿⣿⣿⣿⣿⣿⢿⣛⣻⣿⣶⣿⣿⣿⣿⣿⣿⡇⣴⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠲⣴⣿⣴⣾⢹⣿⣿⠟⠋⢻⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⠿⠛⣻⣿⣿⣿⣿⣿⢳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣯⣿⠿⠁⠀⠀⠈⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⣠⣾⣿⣿⣿⣿⢟⣩⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣳⠟⠁⠀⠀⠀⠀⣼⡇⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⡿⣴⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⠀⠀⠀⠀⠀⢈⠉⠉⢩⡿⠏⠀⣀⣀⠀⠀⠀⣿⠇⠀⢀⣦⢨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢛⣾⣿⣿⣿⣿⣿⣿⢿⣿⣿⠿⠲⠄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣶⢿⣷⣶⡀⠀⢠⣿⠀⢀⣿⠃⠀⠀⠻⣿⠃⠀⠐⣿⠀⠀⢸⡿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⠿⠿⠿⠱⠟⠛⠙⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⣿⣿⢻⣿⠃⠀⣾⡇⠀⢸⣿⠀⠀⠀⢠⣶⡄⠀⢸⣿⠀⠀⣾⡇⠀⠀⠀⠀⠀⣿⣿⣿⣯⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠉⣙⡀⠀⠀⠀⣿⡇⠀⢸⣿⠀⠀⣴⠟⠻⣿⣀⣼⡟⠀⠀⣿⡇⠀⠀⠀⠀⠀⢸⣿⣯⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣤⣠⣶⣦⣴⣿⣿⣆⠀⠀⣿⡇⠀⢸⣿⣦⣀⣿⣶⣾⡿⠟⠉⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⢸⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠙⠻⠋⠙⠋⠙⠛⢻⣿⠀⢀⣿⠃⠀⣼⡟⢿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⣿⠇⠀⠀⠀⠀⠐⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣴⣿⣶⣶⣶⡿⠃⠀⣾⣏⣠⣼⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢾⠟⠉⠉⠛⠛⠉⠀⠀⠀⠙⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

TITLE = "OSINT USERNAME TRACKER"
CREDIT = "coded by Mr Sabaz Ali Khan"

# ANSI colours
G, R, Y, C, W, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[97m", "\033[0m"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Each site: url template, detection method, optional error text
#   status  -> HTTP 200 means found, 404 means not found
#   message -> found unless `error` text appears in the response body
SITES = {
    "GitHub":        {"url": "https://github.com/{}", "method": "status"},
    "GitLab":        {"url": "https://gitlab.com/{}", "method": "status"},
    "Bitbucket":     {"url": "https://bitbucket.org/{}/", "method": "status"},
    "Reddit":        {"url": "https://www.reddit.com/user/{}/about.json", "method": "status"},
    "HackerNews":    {"url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "method": "message", "error": "null"},
    "Dev.to":        {"url": "https://dev.to/{}", "method": "status"},
    "Medium":        {"url": "https://medium.com/@{}", "method": "status"},
    "Keybase":       {"url": "https://keybase.io/{}", "method": "status"},
    "Pinterest":     {"url": "https://www.pinterest.com/{}/", "method": "status"},
    "Twitch":        {"url": "https://www.twitch.tv/{}", "method": "message", "error": "content=\"Twitch is the world"},
    "YouTube":       {"url": "https://www.youtube.com/@{}", "method": "status"},
    "TikTok":        {"url": "https://www.tiktok.com/@{}", "method": "status"},
    "Instagram":     {"url": "https://www.instagram.com/{}/", "method": "status"},
    "X (Twitter)":   {"url": "https://x.com/{}", "method": "status"},
    "Telegram":      {"url": "https://t.me/{}", "method": "message", "error": "tgme_page_extra\"></div>"},
    "Steam":         {"url": "https://steamcommunity.com/id/{}", "method": "message", "error": "The specified profile could not be found"},
    "SoundCloud":    {"url": "https://soundcloud.com/{}", "method": "status"},
    "Behance":       {"url": "https://www.behance.net/{}", "method": "status"},
    "Dribbble":      {"url": "https://dribbble.com/{}", "method": "status"},
    "Flickr":        {"url": "https://www.flickr.com/people/{}/", "method": "status"},
    "Vimeo":         {"url": "https://vimeo.com/{}", "method": "status"},
    "Patreon":       {"url": "https://www.patreon.com/{}", "method": "status"},
    "About.me":      {"url": "https://about.me/{}", "method": "status"},
    "Gravatar":      {"url": "https://en.gravatar.com/{}", "method": "status"},
    "Replit":        {"url": "https://replit.com/@{}", "method": "status"},
    "LeetCode":      {"url": "https://leetcode.com/{}/", "method": "status"},
    "HackerOne":     {"url": "https://hackerone.com/{}", "method": "status"},
    "Bugcrowd":      {"url": "https://bugcrowd.com/{}", "method": "status"},
    "CodePen":       {"url": "https://codepen.io/{}", "method": "status"},
    "Kaggle":        {"url": "https://www.kaggle.com/{}", "method": "status"},
    "Pastebin":      {"url": "https://pastebin.com/u/{}", "method": "status"},
    "npm":           {"url": "https://www.npmjs.com/~{}", "method": "status"},
    "PyPI":          {"url": "https://pypi.org/user/{}/", "method": "status"},
    "DockerHub":     {"url": "https://hub.docker.com/u/{}/", "method": "status"},
    "Linktree":      {"url": "https://linktr.ee/{}", "method": "status"},
    "Spotify":       {"url": "https://open.spotify.com/user/{}", "method": "status"},
    "Chess.com":     {"url": "https://www.chess.com/member/{}", "method": "status"},
    "Lichess":       {"url": "https://lichess.org/@/{}", "method": "status"},
    "Wattpad":       {"url": "https://www.wattpad.com/user/{}", "method": "status"},
    "Tumblr":        {"url": "https://{}.tumblr.com", "method": "status"},
    "WordPress":     {"url": "https://{}.wordpress.com", "method": "status"},
    "Blogger":       {"url": "https://{}.blogspot.com", "method": "status"},
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,40}$")


def show_banner():
    print(f"{C}{BANNER}{X}")
    print(f"{G}{TITLE.center(60)}{X}")
    print(f"{Y}{CREDIT.center(60)}{X}")
    print(f"{W}{'-' * 60}{X}\n")


def check_site(name, cfg, username, timeout, session):
    url = cfg["url"].format(username)
    result = {"site": name, "url": url, "status": "error", "http": None}
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        result["http"] = resp.status_code
        if cfg["method"] == "status":
            if resp.status_code == 200:
                result["status"] = "found"
            elif resp.status_code in (404, 410):
                result["status"] = "not_found"
            else:
                result["status"] = "uncertain"
        else:
            body = resp.text.strip()
            if resp.status_code in (404, 410) or cfg["error"] in body or body == cfg["error"]:
                result["status"] = "not_found"
            elif resp.status_code == 200:
                result["status"] = "found"
            else:
                result["status"] = "uncertain"
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except requests.exceptions.RequestException:
        result["status"] = "error"
    return result


def scan(username, threads, timeout, found_only):
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"})

    print(f"{W}[*] Target username : {G}{username}{X}")
    print(f"{W}[*] Platforms       : {len(SITES)}{X}")
    print(f"{W}[*] Started         : {datetime.now():%Y-%m-%d %H:%M:%S}{X}\n")

    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check_site, n, c, username, timeout, session): n for n, c in SITES.items()}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if r["status"] == "found":
                print(f"{G}[+] {r['site']:<14}{X} {r['url']}")
            elif not found_only:
                tag = {"not_found": f"{R}[-]", "uncertain": f"{Y}[?]",
                       "timeout": f"{Y}[T]", "error": f"{Y}[!]"}[r["status"]]
                print(f"{tag} {r['site']:<14}{X} {r['status']}")

    results.sort(key=lambda r: r["site"].lower())
    elapsed = time.time() - start
    found = [r for r in results if r["status"] == "found"]
    print(f"\n{W}{'-' * 60}{X}")
    print(f"{G}[✓] Found on {len(found)}/{len(SITES)} platforms in {elapsed:.1f}s{X}")
    print(f"{Y}[i] 'Found' means a profile page responded; verify manually before drawing conclusions.{X}\n")
    return results


def save_json(path, username, results):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"username": username, "generated": datetime.now().isoformat(),
                   "credit": CREDIT, "results": results}, f, indent=2)
    print(f"{C}[+] JSON saved to {path}{X}")


def save_csv(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["site", "url", "status", "http"])
        w.writeheader()
        w.writerows(results)
    print(f"{C}[+] CSV saved to {path}{X}")


def main():
    parser = argparse.ArgumentParser(description=f"{TITLE} - {CREDIT}")
    parser.add_argument("username", nargs="?", help="username to search")
    parser.add_argument("-f", "--file", help="file with one username per line")
    parser.add_argument("-t", "--threads", type=int, default=20, help="worker threads (default 20)")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (default 10)")
    parser.add_argument("-o", "--output", help="save results as JSON")
    parser.add_argument("--csv", help="save results as CSV")
    parser.add_argument("--found-only", action="store_true", help="only print matches")
    args = parser.parse_args()

    show_banner()

    usernames = []
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                usernames = [l.strip() for l in f if l.strip()]
        except OSError as e:
            print(f"{R}[!] Cannot read file: {e}{X}")
            sys.exit(1)
    elif args.username:
        usernames = [args.username]
    else:
        try:
            usernames = [input(f"{W}[?] Enter username: {X}").strip()]
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

    for u in usernames:
        if not USERNAME_RE.match(u):
            print(f"{R}[!] Skipping invalid username: {u!r}{X}")
            continue
        try:
            results = scan(u, args.threads, args.timeout, args.found_only)
        except KeyboardInterrupt:
            print(f"\n{R}[!] Interrupted.{X}")
            sys.exit(1)
        suffix = f"_{u}" if len(usernames) > 1 else ""
        if args.output:
            save_json(args.output.replace(".json", f"{suffix}.json") if suffix else args.output, u, results)
        if args.csv:
            save_csv(args.csv.replace(".csv", f"{suffix}.csv") if suffix else args.csv, results)

    print(f"{Y}{CREDIT.center(60)}{X}")


if __name__ == "__main__":
    main()
