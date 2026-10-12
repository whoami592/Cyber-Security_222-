#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Geolocation & Threat Tracker
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Features
  * Geolocation (country, city, coordinates, timezone, ISP, ASN)
  * Proxy / VPN / hosting / mobile detection (ip-api.com, no key needed)
  * Optional reputation lookup via AbuseIPDB (set ABUSEIPDB_KEY env var)
  * Reverse DNS lookup
  * Simple 0-100 risk score with LOW / MEDIUM / HIGH rating
  * Single IP, many IPs, or a file of IPs (one per line)
  * Export results to JSON or CSV

Usage
  python ip_threat_tracker.py 8.8.8.8
  python ip_threat_tracker.py 8.8.8.8 1.1.1.1 --json report.json
  python ip_threat_tracker.py -f ips.txt --csv report.csv
  python ip_threat_tracker.py --self

Only use on IPs you are authorised to investigate. Free ip-api.com tier
allows ~45 requests/minute and is HTTP only; this tool throttles itself.
"""

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠴⠒⠃⠉⠁⠒⠢⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠉⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡇⣀⣠⣴⣆⡤⠦⢄⠀⠀⠀⠀⠀⣾⠤⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣿⣿⣿⣀⣀⣸⠇⠀⠀⠀⡀⢸⣆⠀⠀⠉⠑⠢⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢽⡞⠓⣿⢷⣄⠀⠀⢀⡼⢀⠏⢸⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡶⠶⠶⠤⠤⣤⣤⣤⣤⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠸⣤⡴⠁⠀⢉⣇⣠⠟⣡⡎⠀⢸⠀⠀⢀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀
⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠹⣆⠀⠀⠀⠀⠀⢀⡇⢱⣶⣾⢛⣉⣻⣉⢹⠉⠉⠋⠀⠀⢘⡆⠀⠀⠀⢀⣤⠀⢳⠀⠀⠀⠀⠀
⠀⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀⢀⡇⢸⡿⠿⠿⠿⠿⣿⣿⡤⠤⠤⢤⠀⠀⢷⣠⠀⣠⣿⠏⠀⠀⢧⠀⠀⠀⠀
⠘⠓⠒⠒⠷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⠤⠶⣶⠾⠗⠺⣄⣀⣀⣐⣮⣿⡶⣒⡉⠁⠘⣷⣀⣘⣿⣞⣡⢔⣂⣀⣀⡘⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠙⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⠤⢼⣇⣀⣀⠀⠈⡇⠀⠀⡟⢯⠤⠤⠀⠀⣿⣏⠙⢯⠉⠛⠍⠉⠉⠉⠙⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣾⣿⣿⣿⠟⠻⠶⢶⣇⣬⠿⠶⢶⣾⣿⠏⠀⣸⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠢⠤⣀⣀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⡷⠶⠾⠛⠋⠀⠀⠀⠈⠙⠒⠓⠒⠂⠠⠤⠤⠤⠤⢼⣁⣀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠒⠲⠦⢤⣤⣽⣏⡙⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸
"""

TITLE = "IP GEOLOCATION & THREAT TRACKER"
CREDIT = "Coded by Mr Sabaz Ali Khan | Cyber Security Engineer"

GEO_URL = "http://ip-api.com/json/{ip}"
GEO_FIELDS = ("status,message,country,countryCode,regionName,city,zip,lat,lon,"
              "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 10
THROTTLE = 1.4  # seconds between ip-api calls (~43/min)

C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m",
     "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def show_banner():
    print(C["c"] + BANNER + C["x"])
    print(C["b"] + f"{TITLE:^60}" + C["x"])
    print(C["y"] + f"{CREDIT:^60}" + C["x"])
    print()


def http_get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "ip-threat-tracker/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def classify(ip_str):
    """Return (ip_obj, note). note is non-empty for non-public addresses."""
    ip = ipaddress.ip_address(ip_str)
    if ip.is_private:
        return ip, "private"
    if ip.is_loopback:
        return ip, "loopback"
    if ip.is_link_local:
        return ip, "link-local"
    if ip.is_multicast:
        return ip, "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return ip, "reserved"
    return ip, ""


def geolocate(ip=""):
    try:
        data = http_get_json(GEO_URL.format(ip=urllib.parse.quote(ip)) + "?fields=" + GEO_FIELDS)
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        return {"error": f"geolocation lookup failed: {e}"}
    if data.get("status") != "success":
        return {"error": data.get("message", "lookup failed")}
    return data


def abuse_lookup(ip, key):
    if not key:
        return None
    url = ABUSE_URL + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    try:
        d = http_get_json(url, {"Key": key, "Accept": "application/json",
                                "User-Agent": "ip-threat-tracker/1.0"})
        return d.get("data", {})
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        return {"error": str(e)}


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def score_risk(geo, abuse):
    score, reasons = 0, []
    if geo.get("proxy"):
        score += 30
        reasons.append("proxy/VPN/Tor detected")
    if geo.get("hosting"):
        score += 20
        reasons.append("hosting/datacenter IP")
    if abuse and "abuseConfidenceScore" in abuse:
        a = int(abuse["abuseConfidenceScore"])
        if a:
            score += int(a * 0.6)
            reasons.append(f"AbuseIPDB confidence {a}% ({abuse.get('totalReports', 0)} reports)")
    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"
    return score, level, reasons


def analyse(target, abuse_key, geo_throttle=True):
    result = {"input": target}
    if target:
        try:
            _, note = classify(target)
        except ValueError:
            result["error"] = "invalid IP address"
            return result
        if note:
            result["error"] = f"{note} address - no public geolocation available"
            return result
    geo = geolocate(target)
    if geo_throttle:
        time.sleep(THROTTLE)
    if "error" in geo:
        result["error"] = geo["error"]
        return result
    ip = geo["query"]
    abuse = abuse_lookup(ip, abuse_key)
    score, level, reasons = score_risk(geo, abuse if abuse and "error" not in abuse else None)
    result.update({
        "ip": ip,
        "country": geo.get("country"), "country_code": geo.get("countryCode"),
        "region": geo.get("regionName"), "city": geo.get("city"), "zip": geo.get("zip"),
        "latitude": geo.get("lat"), "longitude": geo.get("lon"),
        "map": f"https://www.openstreetmap.org/?mlat={geo.get('lat')}&mlon={geo.get('lon')}#map=11/{geo.get('lat')}/{geo.get('lon')}",
        "timezone": geo.get("timezone"),
        "isp": geo.get("isp"), "org": geo.get("org"), "asn": geo.get("as"),
        "reverse_dns": geo.get("reverse") or reverse_dns(ip),
        "mobile": geo.get("mobile"), "proxy": geo.get("proxy"), "hosting": geo.get("hosting"),
        "abuse_confidence": (abuse or {}).get("abuseConfidenceScore"),
        "abuse_reports": (abuse or {}).get("totalReports"),
        "abuse_last_reported": (abuse or {}).get("lastReportedAt"),
        "risk_score": score, "risk_level": level, "risk_reasons": reasons,
    })
    if abuse and "error" in abuse:
        result["abuse_error"] = abuse["error"]
    return result


def print_result(r):
    line = "=" * 60
    print(C["b"] + line + C["x"])
    if "error" in r:
        print(f"{C['r']}[!] {r['input'] or 'self'}: {r['error']}{C['x']}")
        return
    col = {"LOW": C["g"], "MEDIUM": C["y"], "HIGH": C["r"]}[r["risk_level"]]
    rows = [
        ("IP", r["ip"]),
        ("Location", f"{r['city']}, {r['region']}, {r['country']} ({r['country_code']}) {r['zip'] or ''}".strip()),
        ("Coordinates", f"{r['latitude']}, {r['longitude']}"),
        ("Map", r["map"]),
        ("Timezone", r["timezone"]),
        ("ISP", r["isp"]),
        ("Organisation", r["org"]),
        ("ASN", r["asn"]),
        ("Reverse DNS", r["reverse_dns"] or "-"),
        ("Proxy/VPN", "YES" if r["proxy"] else "no"),
        ("Hosting/DC", "YES" if r["hosting"] else "no"),
        ("Mobile", "yes" if r["mobile"] else "no"),
    ]
    if r.get("abuse_confidence") is not None:
        rows.append(("AbuseIPDB", f"{r['abuse_confidence']}% confidence, {r['abuse_reports']} reports"))
    for k, v in rows:
        print(f"{C['c']}{k:<13}{C['x']}: {v}")
    print(f"{C['c']}{'Threat level':<13}{C['x']}: {col}{r['risk_level']} ({r['risk_score']}/100){C['x']}")
    for reason in r["risk_reasons"]:
        print(f"{'':<15}- {reason}")


def export(results, json_path, csv_path):
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"{C['g']}[+] JSON saved: {json_path}{C['x']}")
    if csv_path:
        keys = sorted({k for r in results for k in r})
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in results:
                r = dict(r)
                r["risk_reasons"] = "; ".join(r.get("risk_reasons", []))
                w.writerow(r)
        print(f"{C['g']}[+] CSV saved: {csv_path}{C['x']}")


def main():
    ap = argparse.ArgumentParser(description="IP Geolocation & Threat Tracker - coded by Mr Sabaz Ali Khan")
    ap.add_argument("ips", nargs="*", help="one or more IP addresses")
    ap.add_argument("-f", "--file", help="file with one IP per line")
    ap.add_argument("--self", action="store_true", help="look up your own public IP")
    ap.add_argument("--abuse-key", default=os.environ.get("ABUSEIPDB_KEY"),
                    help="AbuseIPDB API key (or set ABUSEIPDB_KEY)")
    ap.add_argument("--json", metavar="FILE", help="export results to JSON")
    ap.add_argument("--csv", metavar="FILE", help="export results to CSV")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        show_banner()

    targets = list(args.ips)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"{C['r']}[!] cannot read {args.file}: {e}{C['x']}")
    if args.self:
        targets.append("")
    if not targets:
        ap.print_help()
        sys.exit(1)
    if not args.abuse_key:
        print(f"{C['y']}[i] No AbuseIPDB key set - reputation check skipped "
              f"(proxy/hosting heuristics still used).{C['x']}\n")

    results = []
    try:
        for t in dict.fromkeys(targets):  # de-duplicate, keep order
            r = analyse(t, args.abuse_key)
            results.append(r)
            print_result(r)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    print("=" * 60)
    export(results, args.json, args.csv)


if __name__ == "__main__":
    main()
