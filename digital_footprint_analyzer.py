#!/usr/bin/env python3
"""
Digital Footprint Analyzer
Coded by Mr Sabaz Ali Khan - Cyber Security Engineer

Self-audit tool: see what is publicly discoverable about YOU (or about
an account/domain you own or have written permission to assess).

Modules
  1. Username scan     - checks public profile URLs on popular platforms
  2. Email check       - breach exposure via Have I Been Pwned (API key needed)
  3. Domain recon      - DNS records, SPF/DMARC email-security posture, WHOIS
  4. Risk score        - simple 0-100 exposure score + recommendations
  5. Report export     - JSON report saved to disk

Install:  pip install requests dnspython python-whois
Usage:    python digital_footprint_analyzer.py -u myusername -e me@mail.com -d mydomain.com
          export HIBP_API_KEY=xxxx   (only needed for the email breach check)
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

BANNER = r"""
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⡋⠍⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢉⡰⣶⣾⣷⢲⣄⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢋⢴⣙⣽⣿⣿⣿⣾⣿⣮⣕⢄⡌⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢣⣼⣾⣿⣿⡟⠋⠙⠙⢻⣿⣿⣿⣧⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣣⣾⣿⣿⣿⣟⣲⠀⠀⠀⣒⣾⣿⣿⣿⣷⡚⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢏⡍⠿⢿⣷⠀⢾⣿⠟⢻⡻⣿⣿⣿⣎⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠸⠿⠿⠳⡍⠀⡿⠳⢿⠷⢟⣿⣿⣿⣿⣎⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⡀⠀⠀⢀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣷⣖⠋⣐⣤⣀⣤⡤⠉⢳⣞⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⢿⠻⣿⡟⠛⠿⣿⡿⣿⡿⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⠁⠂⠹⣿⡯⠡⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⢠⣿⣇⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⡟⣽⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⣃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⣿⣇⢠⡄⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⣡⣶⣻⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⡇⣿⣿⣷⣿⣦⣄⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣼⣆⣈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⡷⣿⣿⣯⣏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣸⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
"""

TITLE = r"""
  ____  _       _ _        _   _____          _                _       _
 |  _ \(_) __ _(_) |_ __ _| | |  ___|__   ___ | |_ _ __  _ __(_)_ __ | |_
 | | | | |/ _` | | __/ _` | | | |_ / _ \ / _ \| __| '_ \| '__| | '_ \| __|
 | |_| | | (_| | | || (_| | | |  _| (_) | (_) | |_| |_) | |  | | | | | |_
 |____/|_|\__, |_|\__\__,_|_| |_|  \___/ \___/ \__| .__/|_|  |_|_| |_|\__|
          |___/                                    |_|     A N A L Y Z E R
"""

CREDIT = "Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer"

C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.name == "nt" and not os.environ.get("WT_SESSION"):
    C = {k: "" for k in C}

UA = {"User-Agent": "Mozilla/5.0 (DigitalFootprintAnalyzer; self-audit)"}

# platform -> (profile URL template, how to tell a profile does NOT exist)
PLATFORMS = {
    "GitHub":      ("https://github.com/{u}", "status"),
    "GitLab":      ("https://gitlab.com/{u}", "status"),
    "Reddit":      ("https://www.reddit.com/user/{u}", "status"),
    "Twitter/X":   ("https://x.com/{u}", "skip"),          # blocks bots; manual check
    "Instagram":   ("https://www.instagram.com/{u}/", "skip"),
    "TikTok":      ("https://www.tiktok.com/@{u}", "status"),
    "Medium":      ("https://medium.com/@{u}", "status"),
    "Dev.to":      ("https://dev.to/{u}", "status"),
    "HackerNews":  ("https://news.ycombinator.com/user?id={u}", "text:No such user"),
    "Pinterest":   ("https://www.pinterest.com/{u}/", "status"),
    "Twitch":      ("https://www.twitch.tv/{u}", "skip"),
    "YouTube":     ("https://www.youtube.com/@{u}", "status"),
    "Telegram":    ("https://t.me/{u}", "text:tgme_page_title"),
    "Keybase":     ("https://keybase.io/{u}", "status"),
    "Steam":       ("https://steamcommunity.com/id/{u}", "text:The specified profile could not be found"),
    "SoundCloud":  ("https://soundcloud.com/{u}", "status"),
    "Docker Hub":  ("https://hub.docker.com/u/{u}", "status"),
    "PyPI":        ("https://pypi.org/user/{u}/", "status"),
}

# how sensitive each platform is for exposure scoring
WEIGHT = {"GitHub": 6, "Twitter/X": 4, "Instagram": 5, "Reddit": 4, "Telegram": 4}


def hr(title):
    print(f"\n{C['c']}{C['b']}=== {title} ==={C['x']}")


# --------------------------------------------------------------------------
# 1. Username scan
# --------------------------------------------------------------------------
def check_platform(name, url_tpl, mode, username):
    url = url_tpl.format(u=username)
    if mode == "skip":
        return name, url, "manual"
    try:
        r = requests.get(url, headers=UA, timeout=8, allow_redirects=True)
        if mode == "status":
            found = r.status_code == 200
        elif mode.startswith("text:"):
            marker = mode[5:]
            if marker == "tgme_page_title":
                found = marker in r.text and "tgme_page_extra" in r.text
            else:
                found = r.status_code == 200 and marker not in r.text
        else:
            found = False
        return name, url, "found" if found else "not found"
    except requests.RequestException:
        return name, url, "error"


def scan_username(username):
    hr(f"USERNAME SCAN: {username}")
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,40}", username):
        print(f"{C['r']}[!] Invalid username format{C['x']}")
        return []
    results = []
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(check_platform, n, t, m, username) for n, (t, m) in PLATFORMS.items()]
        for f in cf.as_completed(futs):
            results.append(f.result())
    for name, url, status in sorted(results):
        col = {"found": C["r"], "not found": C["g"], "manual": C["y"], "error": C["y"]}[status]
        print(f"  {col}[{status.upper():<9}]{C['x']} {name:<12} {url}")
    return [{"platform": n, "url": u, "status": s} for n, u, s in results]


# --------------------------------------------------------------------------
# 2. Email breach check (Have I Been Pwned v3 - requires paid API key)
# --------------------------------------------------------------------------
def check_email(email):
    hr(f"EMAIL BREACH CHECK: {email}")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        print(f"{C['r']}[!] Invalid email format{C['x']}")
        return {"error": "invalid email"}
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        print(f"{C['y']}[~] HIBP_API_KEY not set - skipping. Manual check: https://haveibeenpwned.com{C['x']}")
        return {"skipped": True}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}",
            headers={"hibp-api-key": key, "user-agent": "DigitalFootprintAnalyzer"},
            params={"truncateResponse": "false"},
            timeout=10,
        )
        if r.status_code == 404:
            print(f"{C['g']}[+] No known breaches found{C['x']}")
            return {"breaches": []}
        if r.status_code == 200:
            data = r.json()
            print(f"{C['r']}[!] Found in {len(data)} breach(es):{C['x']}")
            for b in data:
                classes = ", ".join(b.get("DataClasses", [])[:5])
                print(f"    - {b['Name']} ({b.get('BreachDate','?')}): {classes}")
            return {"breaches": [{"name": b["Name"], "date": b.get("BreachDate"),
                                  "data": b.get("DataClasses", [])} for b in data]}
        print(f"{C['y']}[~] HIBP returned HTTP {r.status_code}{C['x']}")
        return {"error": r.status_code}
    except requests.RequestException as e:
        print(f"{C['y']}[~] Network error: {e}{C['x']}")
        return {"error": str(e)}


# --------------------------------------------------------------------------
# 3. Domain recon (only for domains you own / are authorised to assess)
# --------------------------------------------------------------------------
def txt_records(domain):
    try:
        return [b"".join(r.strings).decode() for r in dns.resolver.resolve(domain, "TXT")]
    except Exception:
        return []


def analyze_domain(domain):
    hr(f"DOMAIN RECON: {domain}")
    out = {"records": {}, "issues": []}
    if not re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,}", domain):
        print(f"{C['r']}[!] Invalid domain{C['x']}")
        return out
    if dns is None:
        print(f"{C['y']}[~] dnspython not installed (pip install dnspython){C['x']}")
    else:
        for rtype in ("A", "AAAA", "MX", "NS"):
            try:
                ans = [str(r) for r in dns.resolver.resolve(domain, rtype)]
                out["records"][rtype] = ans
                print(f"  {rtype:<5} {', '.join(ans)}")
            except Exception:
                pass
        spf = [t for t in txt_records(domain) if t.startswith("v=spf1")]
        dmarc = [t for t in txt_records(f"_dmarc.{domain}") if t.startswith("v=DMARC1")]
        if spf:
            print(f"{C['g']}  [+] SPF present{C['x']}: {spf[0]}")
            if "+all" in spf[0] or "?all" in spf[0]:
                out["issues"].append("SPF policy too permissive (+all / ?all)")
        else:
            out["issues"].append("No SPF record - email spoofing is easier")
        if dmarc:
            print(f"{C['g']}  [+] DMARC present{C['x']}: {dmarc[0]}")
            if "p=none" in dmarc[0]:
                out["issues"].append("DMARC policy is p=none (monitor only)")
        else:
            out["issues"].append("No DMARC record - spoofed mail may be delivered")
    if whois is not None:
        try:
            w = whois.whois(domain)
            info = {"registrar": str(w.registrar), "created": str(w.creation_date),
                    "expires": str(w.expiration_date), "org": str(w.org),
                    "emails": str(w.emails)}
            out["whois"] = info
            print(f"  WHOIS registrar: {info['registrar']}")
            print(f"  WHOIS created:   {info['created']}")
            if w.emails or (w.org and str(w.org) != "None"):
                out["issues"].append("WHOIS exposes registrant org/email - enable privacy protection")
        except Exception as e:
            print(f"{C['y']}[~] WHOIS failed: {e}{C['x']}")
    else:
        print(f"{C['y']}[~] python-whois not installed (pip install python-whois){C['x']}")
    for i in out["issues"]:
        print(f"{C['r']}  [!] {i}{C['x']}")
    return out


# --------------------------------------------------------------------------
# 4. Risk score
# --------------------------------------------------------------------------
def risk_score(report):
    score, recs = 0, []
    for r in report.get("usernames", []):
        if r["status"] == "found":
            score += WEIGHT.get(r["platform"], 2)
    if score:
        recs.append("Reuse of one username links your accounts - use different handles for sensitive profiles.")
    br = report.get("email", {}).get("breaches", [])
    if br:
        score += min(40, 8 * len(br))
        recs += ["Change passwords on breached sites and anywhere they were reused.",
                 "Enable 2FA (authenticator app or hardware key) and use a password manager."]
    issues = report.get("domain", {}).get("issues", [])
    score += 8 * len(issues)
    recs += [f"Domain: {i}" for i in issues]
    score = min(100, score)
    level = "LOW" if score < 25 else "MEDIUM" if score < 55 else "HIGH"
    recs += ["Review privacy settings on every public profile.",
             "Search your name/email on Google and request removal of unwanted results."]
    return score, level, recs


def main():
    print(C["c"] + BANNER + C["x"])
    print(C["g"] + TITLE + C["x"])
    print(f"{C['y']}{C['b']}  {CREDIT}{C['x']}\n")

    p = argparse.ArgumentParser(description="Digital Footprint Analyzer - self-audit tool")
    p.add_argument("-u", "--username", help="username/handle to look up")
    p.add_argument("-e", "--email", help="email to check for breaches (HIBP)")
    p.add_argument("-d", "--domain", help="domain you own to analyse")
    p.add_argument("-o", "--output", help="JSON report path (default: footprint_report_<time>.json)")
    p.add_argument("--yes", action="store_true", help="confirm you are authorised to assess these targets")
    a = p.parse_args()

    if not (a.username or a.email or a.domain):
        p.print_help()
        return

    if not a.yes:
        ans = input(f"{C['y']}Only analyse yourself or assets you have written permission to assess. Confirm? [y/N] {C['x']}")
        if ans.strip().lower() != "y":
            sys.exit("Aborted.")

    report = {"tool": "Digital Footprint Analyzer", "author": "Mr Sabaz Ali Khan",
              "generated": datetime.now().isoformat(timespec="seconds")}
    if a.username:
        report["usernames"] = scan_username(a.username)
    if a.email:
        report["email"] = check_email(a.email)
    if a.domain:
        report["domain"] = analyze_domain(a.domain)

    score, level, recs = risk_score(report)
    hr("EXPOSURE SCORE")
    col = {"LOW": C["g"], "MEDIUM": C["y"], "HIGH": C["r"]}[level]
    print(f"  {col}{C['b']}{score}/100 - {level}{C['x']}")
    print("\n  Recommendations:")
    for r in dict.fromkeys(recs):
        print(f"   * {r}")
    report["score"], report["level"], report["recommendations"] = score, level, recs

    path = a.output or f"footprint_report_{datetime.now():%Y%m%d_%H%M%S}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n{C['g']}[+] Report saved: {path}{C['x']}\n")
    print(f"{C['y']}{CREDIT}{C['x']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted")
