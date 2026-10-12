#!/usr/bin/env python3
"""
Phone Number OSINT Tool
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Extracts publicly derivable metadata from phone numbers:
validity, country/region, carrier, line type, time zones, formats.
Optional: enrich with the NumVerify API (set NUMVERIFY_KEY env var).

Install:  pip install phonenumbers
Usage:    python phone_osint.py +923001234567
          python phone_osint.py 03001234567 -r PK
          python phone_osint.py -f numbers.txt -o report.json

Use only for lawful, authorized investigations.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.parse

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone, PhoneNumberType
except ImportError:
    sys.exit("[!] Missing dependency. Run: pip install phonenumbers")

BANNER = """
⠀⠀⠀⠀⠀⣀⣠⠤⠶⠶⣖⡛⠛⠿⠿⠯⠭⠍⠉⣉⠛⠚⠛⠲⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⠋⠁⠀⡉⠁⢐⣒⠒⠈⠁⠀⠀⠀⠈⠁⢂⢅⡂⠀⠀⠘⣧⠀⠀⠀⠀
⠀⠀⣼⠀⠀⠀⠁⠀⠀⠀⠂⠀⠀⠀⠀⢀⣀⣤⣤⣄⡈⠈⠀⠀⠀⠘⣇⠀⠀⠀
⢠⡾⠡⠄⠀⠀⠾⠿⠿⣷⣦⣤⠀⠀⣾⣋⡤⠿⠿⠿⠿⠆⠠⢀⣀⡒⠼⢷⣄⠀
⣿⠊⠊⠶⠶⢦⣄⡄⠀⢀⣿⠀⠀⠀⠈⠁⠀⠀⠙⠳⠦⠶⠞⢋⣍⠉⢳⡄⠈⣧
⢹⣆⡂⢀⣿⠀⠀⡀⢴⣟⠁⠀⢀⣠⣘⢳⡖⠀⠀⣀⣠⡴⠞⠋⣽⠷⢠⠇⠀⣼
⠀⢻⡀⢸⣿⣷⢦⣄⣀⣈⣳⣆⣀⣀⣤⣭⣴⠚⠛⠉⣹⣧⡴⣾⠋⠀⠀⣘⡼⠃
⠀⢸⡇⢸⣷⣿⣤⣏⣉⣙⣏⣉⣹⣁⣀⣠⣼⣶⡾⠟⢻⣇⡼⠁⠀⠀⣰⠋⠀⠀
⠀⢸⡇⠸⣿⡿⣿⢿⡿⢿⣿⠿⠿⣿⠛⠉⠉⢧⠀⣠⡴⠋⠀⠀⠀⣠⠇⠀⠀⠀
⠀⢸⠀⠀⠹⢯⣽⣆⣷⣀⣻⣀⣀⣿⣄⣤⣴⠾⢛⡉⢄⡢⢔⣠⠞⠁⠀⠀⠀⠀
⠀⢸⠀⠀⠀⠢⣀⠀⠈⠉⠉⠉⠉⣉⣀⠠⣐⠦⠑⣊⡥⠞⠋⠀⠀⠀⠀⠀⠀⠀
⠀⢸⡀⠀⠁⠂⠀⠀⠀⠀⠀⠀⠒⠈⠁⣀⡤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠶⢤⣤⣤⣤⣤⡤⠴⠖⠚⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

        PHONE NUMBER OSINT TOOL
        coded by Mr Sabaz Ali Khan
"""

LINE_TYPES = {
    PhoneNumberType.FIXED_LINE: "Fixed line",
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "Toll free",
    PhoneNumberType.PREMIUM_RATE: "Premium rate",
    PhoneNumberType.SHARED_COST: "Shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown",
}


def numverify_lookup(number_e164, api_key):
    """Optional enrichment via NumVerify (free tier is HTTP only)."""
    params = urllib.parse.urlencode(
        {"access_key": api_key, "number": number_e164.lstrip("+")}
    )
    url = f"http://apilayer.net/api/validate?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        return {"error": str(exc)}


def analyze(raw, region=None, api_key=None):
    result = {"input": raw}
    try:
        num = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as exc:
        result["error"] = f"Parse failed: {exc}"
        return result

    result.update({
        "possible": phonenumbers.is_possible_number(num),
        "valid": phonenumbers.is_valid_number(num),
        "country_code": f"+{num.country_code}",
        "national_number": str(num.national_number),
        "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.RFC3966),
        "region_code": phonenumbers.region_code_for_number(num),
        "location": geocoder.description_for_number(num, "en") or "Unknown",
        "carrier": carrier.name_for_number(num, "en") or "Unknown",
        "line_type": LINE_TYPES.get(phonenumbers.number_type(num), "Unknown"),
        "timezones": list(timezone.time_zones_for_number(num)),
    })

    if api_key and result["valid"]:
        result["numverify"] = numverify_lookup(result["e164"], api_key)
    return result


def print_report(r):
    print("=" * 60)
    if "error" in r:
        print(f"[!] {r['input']}  ->  {r['error']}")
        return
    print(f"[+] Input         : {r['input']}")
    print(f"    Possible      : {r['possible']}")
    print(f"    Valid         : {r['valid']}")
    print(f"    E.164         : {r['e164']}")
    print(f"    International : {r['international']}")
    print(f"    National      : {r['national']}")
    print(f"    Country code  : {r['country_code']}  ({r['region_code']})")
    print(f"    Location      : {r['location']}")
    print(f"    Carrier       : {r['carrier']}")
    print(f"    Line type     : {r['line_type']}")
    print(f"    Time zones    : {', '.join(r['timezones']) or 'Unknown'}")
    if "numverify" in r:
        nv = r["numverify"]
        print("    --- NumVerify ---")
        for k in ("carrier", "line_type", "location", "country_name"):
            if k in nv:
                print(f"    {k:<14}: {nv[k]}")
        if "error" in nv:
            print(f"    error         : {nv['error']}")


def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="Phone Number OSINT Tool - coded by Mr Sabaz Ali Khan")
    ap.add_argument("numbers", nargs="*", help="phone number(s), ideally in +CC format")
    ap.add_argument("-r", "--region", help="default region code (e.g. PK, US, GB) for local-format numbers")
    ap.add_argument("-f", "--file", help="text file with one number per line")
    ap.add_argument("-o", "--output", help="save results to a JSON file")
    args = ap.parse_args()

    targets = list(args.numbers)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            sys.exit(f"[!] Cannot read {args.file}: {exc}")

    if not targets:
        entry = input("[?] Enter phone number (e.g. +923001234567): ").strip()
        if entry:
            targets.append(entry)
        else:
            ap.print_help()
            return

    api_key = os.environ.get("NUMVERIFY_KEY")
    results = []
    for t in targets:
        r = analyze(t, args.region, api_key)
        print_report(r)
        results.append(r)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"\n[+] Saved report to {args.output}")

    print("\n[*] Done - coded by Mr Sabaz Ali Khan")


if __name__ == "__main__":
    main()
