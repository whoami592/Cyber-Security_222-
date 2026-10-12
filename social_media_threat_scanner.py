#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Social Media Threat Scanner
---------------------------
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

A defensive, offline analyzer for social media content. Feed it posts,
DMs, comments, bios or usernames that YOU have collected or received and it
flags likely threats:

  * Phishing / scam / giveaway / crypto-fraud language
  * Malicious-looking URLs (shorteners, IP hosts, punycode, lookalike brands)
  * Credential-harvesting and account-takeover lures
  * Threats, harassment and extortion language
  * Leaked sensitive data (emails, phones, API keys, card-like numbers)
  * Bot / spam behaviour (hashtag and mention flooding, repetition)
  * Username impersonation of protected brands / people

Standard library only. No network requests, no scraping.

Usage:
    python social_media_threat_scanner.py --text "Claim your FREE iPhone now!!! bit.ly/xyz"
    python social_media_threat_scanner.py --file posts.txt
    python social_media_threat_scanner.py --file posts.json --json report.json
    python social_media_threat_scanner.py --file comments.csv --handle paypa1_support --protect paypal,mybank
    python social_media_threat_scanner.py --interactive
"""

import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import Counter
from difflib import SequenceMatcher
from urllib.parse import urlparse

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣴⣶⠶⠶⠖⠚⠛⠛⠛⠛⠒⠶⠶⣶⣶⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⡾⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠷⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⡾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣿⠋⠀⠀⠀⠀⢀⣠⣴⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠴⣒⡽⠟⣩⠏⢩⠉⢏⠙⠯⣑⠲⠦⣄⡀⠀⠀⠀⠀⠀⠀⠙⢶⣤⡀⠀⠀⠀⠀⠈⢿⣦⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⡟⠁⠀⠀⣠⢄⣶⣿⠟⠁⠀⠀⠀⠀⢀⣴⠞⠋⠀⣠⠞⠁⠀⣰⠋⠀⣼⠀⠀⢧⡀⠈⠙⢦⡀⠉⠓⠦⣀⡀⠀⠀⠀⠀⠹⣿⣷⣤⢤⡀⠀⠀⠹⣷⡀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⠟⠀⠀⣴⡟⢠⣿⡿⢋⡄⠀⠀⠀⣠⠞⠃⠤⢄⣀⠞⠁⠀⠀⢰⡏⠀⠀⠿⠀⠀⠘⣧⠀⠀⠀⠙⣆⣀⠤⠄⠛⢦⡀⠀⠀⠐⡜⢿⣿⣆⢻⣦⡀⠀⠘⣿⡄⠀⠀⠀
⠀⠀⢀⣾⠏⠀⡠⣸⣿⠇⡾⢋⣴⡟⠀⠀⢠⠞⠃⠀⠀⠀⢠⠟⠙⠒⠒⠤⡞⠀⣤⣤⠶⣤⣤⡀⠘⠀⠐⠒⠊⠙⣧⠀⠀⠀⠀⠙⣄⠀⠀⠹⣶⣝⠻⡄⣿⣷⢠⡀⠘⣿⡄⠀⠀
⠀⠀⣼⠟⠀⣼⠁⣿⡟⣠⣾⣿⠟⠁⠀⡴⠋⠀⠀⠀⠀⢠⠏⠀⠀⠀⠀⠀⡇⠀⢻⣿⢶⢸⣿⡇⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠈⢳⡀⠀⠙⢿⣷⣄⢸⣿⡇⣷⡀⠘⣿⡄⠀
⠀⣸⡿⠀⢸⣿⠀⣿⣽⡿⢋⡵⠀⢀⡾⠁⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⠀⠀⠀⠀⠹⡄⠀⠸⣏⠿⣷⣿⠃⣿⣷⠀⢹⣧⠀
⠀⣿⠇⠀⣼⣿⡇⣼⢋⣴⡿⠁⠀⡼⠀⠉⠒⠶⠦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡀⠤⠴⠂⠈⠀⢹⡀⠀⢹⣷⣌⢻⡄⣿⣿⠀⠀⢿⡄
⢸⡟⠀⣴⢹⣿⡇⣱⣿⡿⠁⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢴⣿⡷⠤⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⠀⣻⣿⣷⡀⣿⣿⠀⠀⢸⡇
⢸⡇⠀⣿⠘⣿⣿⣿⠏⣰⠀⠀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⢻⠙⢿⣧⣿⡇⢠⡇⠀⣿
⣾⠁⠸⣿⡄⠹⡿⠃⣴⡟⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣯⣿⣭⣥⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⣧⠈⢻⡿⠀⣾⡇⠀⣿
⣿⠀⠀⣿⣷⡀⠇⣼⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⡇⠀⢨⣿⣇⠀⠀⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡁⠀⠸⣿⣷⡈⠇⣼⣿⠇⠀⣿
⢿⡄⢀⢻⣿⣷⢸⣿⡟⢀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⢠⣶⣶⣾⣿⣿⣿⣿⡿⠀⠀⠉⣿⡈⠀⠀⢹⣿⣿⣿⣿⣿⣶⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢠⠸⣿⡇⣰⣿⡿⠀⠀⣿
⢸⡇⢸⡄⠻⣿⣼⣿⠁⣸⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⢰⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢸⠇⠀⣼⡀⢿⡇⣿⡟⢁⡇⠀⣿
⢸⣧⠀⣿⣄⠘⢿⡟⢠⣿⡇⠀⠹⡆⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⢸⣿⡇⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⢀⡿⠀⢀⣿⡇⢸⣿⠟⢠⣾⠇⢸⡇
⠀⣿⡄⠙⣿⣷⣌⠓⢸⣿⡗⢄⠀⢱⡀⣀⣤⠴⠖⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⢸⣿⡇⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠓⠶⢤⣄⣀⣼⠁⢠⣾⣿⣧⠸⢁⣶⣿⠟⠀⣾⠃
⠀⢹⣷⠀⠈⢿⣿⣷⡸⣿⡇⠘⣦⡀⢣⡀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⣸⠃⣰⡏⢸⣿⡏⣴⣿⣿⠋⠀⣸⡿⠀
⠀⠀⢻⣦⠘⣦⠙⠿⣷⣿⣿⠀⣿⣧⠀⠳⡄⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢀⡼⠁⣰⣿⠁⢸⣟⣼⡿⠛⣁⠇⢠⣿⠃⠀
⠀⠀⠈⢿⣆⠘⢿⣦⣈⠙⠿⣇⢸⣿⣧⢀⠈⠂⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠠⠋⢀⣠⣿⡿⢠⠿⠛⢁⣠⣶⠏⢠⣿⠃⠀⠀
⠀⠀⠀⠈⢿⣆⠈⠻⣿⣷⣶⣬⡀⢻⣿⡎⢳⣄⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣠⡶⢋⣿⣿⢁⣡⣴⣶⣿⠿⠃⢠⣾⠋⠀⠀⠀
⠀⠀⠀⠀⠈⢻⣧⡀⠈⢙⠿⣿⣿⣷⣿⣷⡄⢿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢁⣼⣿⣵⣿⣿⠿⢟⠁⠀⣰⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠹⣷⣄⠈⢳⣤⣈⣉⠉⠙⠛⠆⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠱⠞⠛⠉⣉⣁⣠⡴⠃⢀⣴⡟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⡀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣶⡿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⢿⣷⣾⣿⣿⣿⣿⣿⠿⠟⠋⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⣦⣄⠀⠰⣬⣉⣉⣉⣉⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣀⣉⣉⣉⣉⣩⠴⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣤⡈⠙⠛⠿⠿⢿⠿⠿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⠿⠿⠿⠿⠟⠛⠁⣠⣶⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣷⣦⣀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⢀⣠⣶⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢶⣤⣄⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⣤⣴⠾⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "SOCIAL MEDIA THREAT SCANNER"
CREDIT = "coded by Mr Sabaz Ali Khan"
ROLE = "Cyber Security Engineer"
VERSION = "1.0"

# --------------------------------------------------------------------------
# Colours
# --------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD, DIM = "91", "92", "93", "96", "95", "1", "2"


def show_banner():
    print(c(BANNER, CYAN))
    print(c(f"  {TITLE}  v{VERSION}", BOLD))
    print(c(f"  {CREDIT} | {ROLE}", GREEN))
    print(c("  " + "=" * 60, DIM))
    print()


# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------
# (rule id, category, weight, compiled regex, description)
def _r(pattern):
    return re.compile(pattern, re.IGNORECASE)


TEXT_RULES = [
    # Scam / giveaway / fraud
    ("SCAM_GIVEAWAY", "Scam", 20,
     _r(r"\b(free (iphone|gift|giveaway|crypto|bitcoin|money|followers|robux|v-?bucks)|you(?:'| ha)ve won|"
        r"claim your (prize|reward|gift)|congratulations[, ]+(you|winner)|lucky winner)\b"),
     "Giveaway / prize scam language"),
    ("SCAM_CRYPTO", "Scam", 25,
     _r(r"\b(double your (bitcoin|btc|eth|crypto|money)|guaranteed (returns?|profit)|"
        r"send \d*\.?\d* ?(btc|eth|usdt)|airdrop.{0,20}connect (your )?wallet|pump and dump|"
        r"100% (profit|roi)|risk[- ]free (investment|trading))\b"),
     "Crypto / investment fraud language"),
    ("SCAM_ADVANCE_FEE", "Scam", 20,
     _r(r"\b(processing fee|release fee|western union|moneygram|gift ?cards?|inheritance|"
        r"beneficiary|wire (the )?(money|funds))\b"),
     "Advance-fee / payment-fraud language"),
    ("SCAM_ROMANCE_JOB", "Scam", 15,
     _r(r"\b(work from home.{0,25}\$\d+|earn \$?\d+.{0,15}(per|a) (day|hour)|"
        r"dm me (to|for) (start|earn|invest)|whatsapp me|telegram me)\b"),
     "Job / romance / DM-funnel scam language"),
    # Phishing / credential harvest
    ("PHISH_ACCOUNT", "Phishing", 25,
     _r(r"\b(verify your (account|identity|password)|account (has been |will be )?(suspended|locked|disabled|limited)|"
        r"unusual (login|activity|sign[- ]?in)|confirm your (login|password|details)|"
        r"security alert|reset your password (now|immediately))\b"),
     "Account-takeover / credential-harvesting lure"),
    ("PHISH_COPYRIGHT", "Phishing", 25,
     _r(r"\b(copyright (violation|infringement|notice)|appeal (this|your) (decision|ban)|"
        r"your page (will be|is being) (deleted|removed)|blue ?badge|verification badge.{0,20}(apply|claim))\b"),
     "Fake copyright / verification-badge lure"),
    ("PHISH_2FA", "Phishing", 30,
     _r(r"\b(send (me )?(the|your) (otp|code|2fa|verification code)|share (your )?(otp|pin|cvv)|"
        r"enter your (otp|pin|cvv|seed phrase|recovery phrase))\b"),
     "OTP / PIN / seed-phrase harvesting"),
    # Urgency / pressure
    ("URGENCY", "Social Engineering", 10,
     _r(r"\b(act now|urgent(ly)?|immediately|within (24|48) hours|last chance|limited time|expires (today|soon)|"
        r"don'?t (miss|ignore)|final warning)\b"),
     "Urgency / pressure tactic"),
    # Malware lures
    ("MALWARE_LURE", "Malware", 20,
     _r(r"\b(download (the )?(crack|keygen|mod apk|cheat|hack|free vpn)|cracked (software|apk)|"
        r"install (this )?(update|plugin|extension) to (view|watch|see)|you need to update (your )?(browser|flash))\b"),
     "Malware / trojanised-download lure"),
    # Threats / harassment
    ("THREAT_VIOLENCE", "Threat", 35,
     _r(r"\b(i(?:'| wi)ll (kill|hurt|find|destroy) you|you(?:'| a)re (dead|going to die)|"
        r"i know where you (live|work)|watch your back|you will regret)\b"),
     "Direct threat language"),
    ("THREAT_EXTORTION", "Threat", 35,
     _r(r"\b(i have (your )?(photos|videos|nudes|recording|password)|"
        r"pay (me )?(or|else)|i will (leak|expose|publish|release)|send (me )?(money|btc|bitcoin) or)\b"),
     "Extortion / sextortion language"),
    ("HARASSMENT", "Harassment", 15,
     _r(r"\b(kill yourself|kys|nobody (likes|wants) you|go die|worthless (idiot|loser))\b"),
     "Targeted harassment / abuse"),
    ("DOXXING", "Harassment", 25,
     _r(r"\b(dox(x)?(ed|ing)?|leak(ed)? (his|her|their) (address|number|info)|home address of)\b"),
     "Doxxing language"),
]

SENSITIVE_PATTERNS = [
    ("LEAK_EMAIL", 5, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "Email address exposed"),
    ("LEAK_PHONE", 5, re.compile(r"(?<!\d)(\+?\d{1,3}[\s-]?)?(\(?\d{3,4}\)?[\s-]?)\d{3}[\s-]?\d{4}(?!\d)"),
     "Phone number exposed"),
    ("LEAK_CARD", 25, re.compile(r"\b(?:\d[ -]?){13,16}\b"), "Card-like number exposed"),
    ("LEAK_AWS_KEY", 40, re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key exposed"),
    ("LEAK_API_KEY", 35, re.compile(r"\b(sk|pk|api|key|token)[-_][A-Za-z0-9]{20,}\b", re.IGNORECASE),
     "API key / token-like string exposed"),
    ("LEAK_PRIVATE_KEY", 50, re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Private key exposed"),
    ("LEAK_SEED", 40, re.compile(r"\b(?:[a-z]{3,8}\s){11,23}[a-z]{3,8}\b"),
     "Possible 12/24-word seed phrase"),
]

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"')]+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|io|ly|gl|co|me|xyz|top|click|link|tk|ml|ga|cf|gq)(?:/[^\s<>"')]*)?)""")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "bl.ink", "lnkd.in", "s.id",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "zip", "mov",
    "country", "kim", "loan", "men", "party", "review", "stream", "gdn", "support",
}
DEFAULT_BRANDS = [
    "facebook", "instagram", "twitter", "whatsapp", "telegram", "tiktok", "snapchat", "linkedin",
    "youtube", "google", "microsoft", "apple", "amazon", "paypal", "netflix", "binance", "coinbase",
    "metamask", "discord", "steam", "outlook", "dropbox",
]
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


# --------------------------------------------------------------------------
# Analysis helpers
# --------------------------------------------------------------------------
def registered_domain(host):
    """Rough eTLD+1 (handles a few common 2-level suffixes)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in {"co.uk", "com.pk", "com.au", "co.in", "com.br", "co.jp", "org.uk"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_url(raw, brands):
    findings = []
    url = raw if re.match(r"(?i)^https?://", raw) else "http://" + raw
    try:
        p = urlparse(url)
    except ValueError:
        return [("URL_MALFORMED", 10, "Malformed URL")]
    host = (p.hostname or "").lower()
    if not host:
        return [("URL_MALFORMED", 10, "Malformed URL")]
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if host in SHORTENERS or reg in SHORTENERS:
        findings.append(("URL_SHORTENER", 12, f"Link shortener hides destination ({reg})"))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append(("URL_IP_HOST", 25, "URL uses a raw IP address instead of a domain"))
    if "xn--" in host:
        findings.append(("URL_PUNYCODE", 25, "Punycode (possible homograph / lookalike domain)"))
    if "@" in (p.netloc or ""):
        findings.append(("URL_USERINFO", 25, "URL contains '@' (credential-style redirect trick)"))
    if tld in SUSPICIOUS_TLDS:
        findings.append(("URL_BAD_TLD", 12, f"Frequently abused TLD (.{tld})"))
    if host.count(".") >= 4:
        findings.append(("URL_SUBDOMAINS", 10, "Excessive subdomains"))
    if p.scheme == "http":
        findings.append(("URL_NO_TLS", 5, "Not using HTTPS"))
    if len(url) > 120:
        findings.append(("URL_LONG", 5, "Unusually long URL"))
    if re.search(r"(?i)(login|signin|verify|secure|account|update|wallet|recover|password)", host + p.path) \
            and reg.split(".")[0] not in brands:
        findings.append(("URL_KEYWORDS", 10, "Credential-themed keywords on non-brand domain"))

    # Brand lookalike / impersonation
    label = reg.split(".")[0]
    norm = label.translate(LEET).replace("-", "")
    for b in brands:
        if label == b:
            break  # genuine brand label (TLD not verified)
        if b in norm or SequenceMatcher(None, norm, b).ratio() >= 0.84:
            findings.append(("URL_LOOKALIKE", 35, f"Domain '{reg}' imitates brand '{b}'"))
            break
        if b in host and reg.split(".")[0] != b:
            findings.append(("URL_BRAND_SUBDOMAIN", 30, f"Brand '{b}' used in subdomain/path of '{reg}'"))
            break
    return findings


def analyze_behaviour(text):
    f = []
    hashtags = re.findall(r"#\w+", text)
    mentions = re.findall(r"@\w+", text)
    if len(hashtags) >= 8:
        f.append(("BOT_HASHTAGS", 8, f"Hashtag flooding ({len(hashtags)})"))
    if len(mentions) >= 6:
        f.append(("BOT_MENTIONS", 10, f"Mass-mention spam ({len(mentions)} mentions)"))
    letters = [ch for ch in text if ch.isalpha()]
    if len(letters) > 20 and sum(ch.isupper() for ch in letters) / len(letters) > 0.6:
        f.append(("SHOUTING", 5, "Excessive capitalisation"))
    if re.search(r"[!?]{4,}", text):
        f.append(("EXCLAIM", 4, "Excessive punctuation"))
    emoji = re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", text)
    if len(emoji) >= 10:
        f.append(("EMOJI_SPAM", 5, "Emoji flooding"))
    words = re.findall(r"\w+", text.lower())
    if len(words) >= 12:
        top, cnt = Counter(words).most_common(1)[0]
        if cnt / len(words) > 0.4 and len(top) > 2:
            f.append(("REPETITION", 6, f"Repetitive text ('{top}')"))
    return f


def analyze_handle(handle, protected):
    findings = []
    h = handle.lstrip("@").lower()
    norm = h.translate(LEET).replace("_", "").replace(".", "").replace("-", "")
    for name in protected:
        n = name.lower()
        if h == n:
            continue
        ratio = SequenceMatcher(None, norm, n).ratio()
        if n in norm or ratio >= 0.82:
            findings.append(("HANDLE_IMPERSONATION", 35, f"Handle '{handle}' resembles protected name '{name}'"))
            break
    if re.search(r"(support|official|help|admin|security|service|verify)", h) and findings:
        findings.append(("HANDLE_AUTHORITY", 15, "Authority keyword combined with lookalike handle"))
    if re.search(r"\d{5,}$", h):
        findings.append(("HANDLE_AUTOGEN", 6, "Auto-generated style username (long digit tail)"))
    return findings


def luhn_ok(num):
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def scan_text(text, brands, handle=None, protected=None):
    """Return dict with score, level and findings for one piece of content."""
    findings = []
    for rid, cat, weight, rx, desc in TEXT_RULES:
        m = rx.search(text)
        if m:
            findings.append({"rule": rid, "category": cat, "weight": weight, "detail": desc,
                             "evidence": m.group(0)[:80]})

    for rid, weight, rx, desc in SENSITIVE_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        if rid == "LEAK_CARD" and not luhn_ok(m.group(0)):
            continue
        if rid == "LEAK_PHONE" and len(re.sub(r"\D", "", m.group(0))) < 9:
            continue
        findings.append({"rule": rid, "category": "Data Leak", "weight": weight, "detail": desc,
                         "evidence": mask(m.group(0))})

    urls = [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]
    for u in dict.fromkeys(urls):
        for rid, weight, desc in analyze_url(u, brands):
            findings.append({"rule": rid, "category": "Malicious URL", "weight": weight,
                             "detail": desc, "evidence": u[:80]})

    for rid, weight, desc in analyze_behaviour(text):
        findings.append({"rule": rid, "category": "Spam/Bot", "weight": weight, "detail": desc, "evidence": ""})

    if handle:
        for rid, weight, desc in analyze_handle(handle, protected or []):
            findings.append({"rule": rid, "category": "Impersonation", "weight": weight,
                             "detail": desc, "evidence": handle})

    # Combine: sum weights, with a bonus when several categories co-occur
    score = sum(f["weight"] for f in findings)
    cats = {f["category"] for f in findings}
    if len(cats) >= 3:
        score += 10
    score = min(score, 100)
    return {"score": score, "level": level_for(score), "findings": findings, "urls": urls}


def mask(s):
    s = s.strip()
    return s if len(s) <= 6 else s[:3] + "*" * (len(s) - 5) + s[-2:]


def level_for(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "SAFE"


LEVEL_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "SAFE": GREEN}


# --------------------------------------------------------------------------
# Input loading
# --------------------------------------------------------------------------
def load_items(path):
    """Return list of dicts: {'text':..., 'handle':optional}."""
    ext = os.path.splitext(path)[1].lower()
    items = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        if ext == ".json":
            data = json.load(fh)
            if isinstance(data, dict):
                data = data.get("posts") or data.get("items") or [data]
            for d in data:
                if isinstance(d, str):
                    items.append({"text": d})
                elif isinstance(d, dict):
                    items.append({"text": str(d.get("text") or d.get("content") or d.get("message") or ""),
                                  "handle": d.get("handle") or d.get("username") or d.get("author")})
        elif ext == ".csv":
            for row in csv.DictReader(fh):
                low = {k.lower(): v for k, v in row.items() if k}
                items.append({"text": low.get("text") or low.get("content") or low.get("message") or "",
                              "handle": low.get("handle") or low.get("username") or low.get("author")})
        else:
            for line in fh:
                if line.strip():
                    items.append({"text": line.strip()})
    return [i for i in items if i["text"]]


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_result(idx, item, res, verbose=True):
    lvl = res["level"]
    preview = item["text"].replace("\n", " ")
    preview = preview[:90] + ("..." if len(preview) > 90 else "")
    head = f"[{idx:03d}] {lvl:<8} score={res['score']:>3}"
    print(c(head, LEVEL_COLOR[lvl] + ";" + BOLD) if USE_COLOR else head)
    if item.get("handle"):
        print(f"      handle : {item['handle']}")
    print(f"      content: {preview}")
    if verbose:
        for f in sorted(res["findings"], key=lambda x: -x["weight"]):
            ev = f"  -> {f['evidence']}" if f["evidence"] else ""
            print(f"      {c('!', YELLOW)} [{f['category']}] {f['detail']} (+{f['weight']}){c(ev, DIM)}")
    print()


def print_summary(results):
    total = len(results)
    counts = Counter(r["level"] for _, r in results)
    cats = Counter(f["category"] for _, r in results for f in r["findings"])
    print(c("=" * 66, DIM))
    print(c("  SCAN SUMMARY", BOLD))
    print(c("=" * 66, DIM))
    print(f"  Items scanned : {total}")
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"):
        print(f"  {lvl:<9}: {c(str(counts.get(lvl, 0)), LEVEL_COLOR[lvl])}")
    if cats:
        print("\n  Top threat categories:")
        for cat, n in cats.most_common(6):
            print(f"    - {cat}: {n}")
    print(c(f"\n  {TITLE} | {CREDIT}", GREEN))
    print()


def save_json(path, results):
    out = {
        "tool": TITLE,
        "version": VERSION,
        "author": "Mr Sabaz Ali Khan",
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "results": [{"content": it["text"], "handle": it.get("handle"), **res} for it, res in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print(c(f"  Report saved to {path}", GREEN))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=f"{TITLE} - {CREDIT}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--text", help="Scan a single piece of text (post, DM, comment, bio)")
    ap.add_argument("--file", help="Scan a .txt (one item per line), .json or .csv file")
    ap.add_argument("--handle", help="Username/handle to check for impersonation (used with --text)")
    ap.add_argument("--protect", help="Comma-separated brand/people names to protect from impersonation")
    ap.add_argument("--interactive", action="store_true", help="Interactive scanning mode")
    ap.add_argument("--json", metavar="OUT.json", help="Save full report as JSON")
    ap.add_argument("--min-level", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Only display items at or above this level")
    ap.add_argument("--quiet", action="store_true", help="Hide per-finding details")
    ap.add_argument("--no-banner", action="store_true", help="Do not print the banner")
    args = ap.parse_args()

    if not args.no_banner:
        show_banner()

    brands = list(dict.fromkeys(DEFAULT_BRANDS + [p.strip().lower() for p in (args.protect or "").split(",") if p.strip()]))
    protected = brands

    items = []
    if args.text:
        items.append({"text": args.text, "handle": args.handle})
    if args.file:
        try:
            items.extend(load_items(args.file))
        except (OSError, ValueError) as e:
            print(c(f"  Error reading file: {e}", RED))
            sys.exit(1)

    order = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    results = []

    def process(item, idx):
        res = scan_text(item["text"], brands, item.get("handle"), protected)
        results.append((item, res))
        if args.min_level is None or order.index(res["level"]) >= order.index(args.min_level):
            print_result(idx, item, res, verbose=not args.quiet)

    if args.interactive:
        print(c("  Interactive mode. Paste content to scan. Optional: 'handle: @name' on the first line.", DIM))
        print(c("  Type 'exit' to quit and see the summary.\n", DIM))
        n = 0
        while True:
            try:
                line = input(c("scan> ", CYAN)).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.lower() in {"exit", "quit", "q"}:
                break
            if not line:
                continue
            handle = None
            m = re.match(r"(?i)^handle:\s*(\S+)\s*\|?\s*(.*)$", line)
            if m:
                handle, line = m.group(1), m.group(2)
            n += 1
            process({"text": line, "handle": handle}, n)
    elif items:
        for i, it in enumerate(items, 1):
            process(it, i)
    else:
        ap.print_help()
        sys.exit(0)

    if results:
        print_summary(results)
        if args.json:
            save_json(args.json, results)


if __name__ == "__main__":
    main()
