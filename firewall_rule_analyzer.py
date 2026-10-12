#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Firewall Rule Analyzer
======================
Author : Mr Sabaz Ali Khan - Cyber Security Engineer

Audits firewall rule sets and reports:
  * Shadowed rules      (never match because an earlier rule covers them)
  * Redundant rules     (an earlier rule with the same action already covers them)
  * Conflicting rules   (overlapping rules with opposite actions - order dependent)
  * Overly permissive   (any/any allow, huge port ranges)
  * Risky exposed services (Telnet, SMB, RDP, databases, Docker API, ...)
  * Missing default-deny and missing logging on the catch-all deny
  * Disabled rules

Supported input formats:
  * JSON         (list of rules, or {"rules": [...], "policies": {...}})
  * CSV          (header: chain,name,action,protocol,source,destination,sport,dport,enabled,log)
  * iptables-save output  (-A CHAIN ... -j ACCEPT|DROP|REJECT)

Usage:
  python firewall_rule_analyzer.py --sample                     # write sample_rules.json
  python firewall_rule_analyzer.py sample_rules.json
  python firewall_rule_analyzer.py rules.csv --json-out report.json
  iptables-save > rules.v4 && python firewall_rule_analyzer.py rules.v4
"""

import argparse
import csv
import ipaddress
import json
import os
import shlex
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

VERSION = "1.0"
AUTHOR = "Mr Sabaz Ali Khan"
TITLE = "Cyber Security Engineer"

BANNER_ART = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠶⠟⠛⠛⠻⠶⠶⣶⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡾⠋⣡⣴⣾⣿⣿⣿⣶⣶⣦⣤⣉⣉⠛⠛⠷⢶⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⢉⣤⣾⣿⣿⣿⡿⠋⠁⠀⠀⠈⠉⠙⠛⠿⢷⣶⣤⣄⣉⠙⠛⠷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⢁⣴⣿⣿⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡟⠿⢶⣤⣄⠉⠻⣶⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⢁⣴⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⣀⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠙⠓⠦⢄⣈⣻⣷⣄⠈⠻⣷⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠟⢁⣴⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⣠⣾⣿⣛⠛⠛⠻⣿⣇⠀⠀⠀⠀⣤⣄⣀⠀⠈⠉⠛⠻⠃⠀⠈⠻⣦⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⢁⣴⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⢠⣾⡿⠋⠉⠛⠻⠶⣶⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⣸⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠁⣰⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⢀⣴⡿⠿⠿⢷⣶⣤⣀⣀⠀⢹⣿⡄⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⣠⡾⠟⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠀⣼⣿⣿⣿⠟⠁⠀⠀⠀⠀⢀⣴⣿⣿⣀⡀⠀⠀⠀⠉⠙⠛⠻⢿⣿⣇⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣇⣴⡟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠀⣸⣿⣿⣿⠋⠀⠀⠀⠀⠀⢠⣾⡟⠉⠉⠛⠛⠿⢷⣶⣤⣄⣀⠀⠀⢸⣿⡄⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⢠⣿⣯⣀⣀⡀⠀⠀⠀⠀⠀⠈⠉⠙⠛⢿⣿⡿⢁⣀⠀⠀⠹⣿⣿⠟⠋⣹⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⢹⣿⣿⣇⠀⠀⠀⠀⠀⣿⡟⠉⠛⠛⠻⠿⠷⣶⣦⣤⣄⣀⣀⢀⣾⡟⣰⠟⠉⠳⣆⠀⠀⠀⣀⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⢻⣿⣿⡄⠀⠀⠀⠀⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⣿⡿⢰⡏⠀⠀⠀⠈⠛⠶⠾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⢻⣿⣿⡀⠀⠀⠀⢹⣿⣦⣤⣤⣤⣤⣀⣀⣀⣀⣀⡀⢀⣿⡇⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣄⠀⢻⣿⣷⡀⠀⠀⠀⢿⣿⠉⠉⠉⠉⠙⠛⠛⠛⠛⠛⠻⣿⡇⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠀⢻⣿⣷⡀⠀⠀⠈⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣆⠀⢻⣿⣿⡄⠀⠀⠘⣿⣦⣤⣤⣤⣤⣤⣤⣤⣤⣴⣿⡇⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⠀⢻⣿⣿⡄⠀⠀⠘⣿⣏⠉⠉⠉⠉⠉⠀⠀⠀⢻⣿⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣧⠀⠻⣿⣿⡄⠀⠀⠹⣿⡄⠀⠀⠀⠀⠀⠀⠀⢸⣿⡄⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠹⣿⣿⡄⠀⠀⠹⣿⣄⣤⣤⣤⣤⣤⣶⣾⣿⣧⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⡀⠹⣿⣿⡄⠀⠀⢹⣿⡉⠉⠁⠀⠀⠀⠀⢸⣿⡌⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠹⣿⣿⡄⠀⠀⢻⣷⡀⠀⠀⠀⠀⠀⠀⣿⣇⢹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⡄⠹⣿⣿⡄⠀⠀⢿⣷⣤⣤⣴⣶⠶⠿⠿⣿⡌⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡄⠹⣿⣿⡆⠀⠈⢿⣯⠀⠀⠀⠀⠀⠀⢿⣧⢹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠹⣿⣿⣄⠀⠘⣿⣧⠀⠀⢀⣀⣀⣼⣿⡄⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠹⣿⣿⡄⠀⠘⣿⣿⠟⠛⠋⠉⠉⢻⣷⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣆⠹⣿⣿⡄⠀⠘⣿⣆⠀⠀⠀⠀⣸⣿⡇⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠹⣿⣿⡄⠀⠸⣿⣶⡶⠿⠛⠋⢻⣿⡘⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⢹⣿⣿⡀⠀⠹⣿⡄⠀⠀⠀⣀⣿⣧⢹⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡆⢻⣿⣷⡀⠀⢹⣿⣶⠶⠟⠛⠻⣿⡄⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⢻⣿⣧⠀⠀⢻⣿⠀⠀⠀⣀⣿⣧⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠒⠛⠛⠛⠒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠈⢿⣿⣇⠀⠈⢿⣷⡶⠟⠛⠻⣿⡄⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠟⠁⢀⣀⠀⢶⣶⣶⣤⡈⠙⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠘⣿⣿⡆⠀⠘⣿⡆⠀⠀⣀⣿⣧⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⠾⠋⢀⣠⣾⡿⢿⣷⡄⠻⣿⣿⣿⣷⣄⡉⠳⣄⠀⠀⠀⠀⠀⠀⠀⣿⡀⢻⣿⣿⡀⠀⢻⣿⡾⠟⠋⢹⣿⡈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠞⠁⢀⣴⣿⠟⠉⠀⠀⠙⣿⣦⡈⠻⣿⣿⣿⣿⣦⡈⠻⣦⡀⠀⠀⠀⠀⢹⡇⠸⣿⣿⣇⠀⠘⣿⣆⣀⣤⣼⣿⡇⠻⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠞⠁⢀⣴⡿⠋⠁⠀⠀⠀⢀⣴⠟⠻⣿⣦⡈⠻⣿⣿⣿⣿⣷⣄⠙⢦⡀⠀⠀⢸⣷⠀⣿⣿⣿⠀⠀⣿⣿⠋⠉⠀⣿⡇⢠⣄⡉⠛⢶⣄⠀⠀⠀⠀⠀
⠀⠀⠀⢰⠋⠀⠀⠿⣿⣦⣄⡀⠀⢀⣴⡿⠁⠀⠀⢈⣿⢿⣶⣄⡙⠻⢿⣿⣿⣷⣦⡙⢷⣤⣸⣿⠀⣿⣿⣿⡇⠀⣿⣿⣤⣶⢾⣿⡇⢸⣿⣿⣷⣤⡈⠻⢦⡀⠀⠀
⠀⠀⠀⠘⣧⠀⠀⠀⠈⠙⠻⢿⣷⣿⣏⡀⠀⠀⣠⡿⠃⠀⠉⢻⣿⣷⣦⣬⣙⣛⠻⠿⠶⠈⠻⠏⢠⣿⣿⣿⡇⠀⣿⡟⠉⠀⣸⣿⠃⢸⣿⣿⣿⡿⠟⢀⡀⠹⣦⠀
⠀⠀⣀⡴⠋⠀⣠⣤⣄⠀⠀⠀⠈⠉⠛⠿⣷⣶⣿⣀⡀⠀⢠⡿⠁⠀⠉⣹⡿⠛⠿⠿⣿⣿⠂⠀⣼⣿⣿⣿⠁⢠⣿⣷⡾⢿⣿⠏⠀⠉⠉⠉⢁⣀⣴⣿⣿⣆⠘⣧
⣠⠞⠋⠀⠴⣾⣿⣿⣿⣿⣦⣄⡀⠀⠀⠀⠀⠈⠙⠛⠿⢿⣿⣷⣤⣤⣤⣿⣥⣤⣴⣿⠟⠁⢀⣼⣿⣿⣿⠏⢀⣾⡟⢁⣴⣿⠏⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿
⠻⠦⣤⣀⡀⠀⠈⠉⠛⠻⠿⢿⣿⣷⣶⣤⣀⠘⠻⠶⣦⣤⣀⣉⠉⠙⠛⠛⠛⠉⠉⠀⣀⣴⣿⣿⣿⡿⠋⣠⣾⣿⣷⡿⠟⠁⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⣰⠏
⠀⠀⠀⠈⠉⠛⠓⠶⠦⣤⣄⣀⣀⡈⠉⠉⠛⠛⠷⠦⠀⠈⠉⠛⠛⠿⠿⠷⣾⣿⣿⣿⡿⠿⠿⠛⠁⠀⠀⠙⠛⠋⠁⠀⠀⠺⠿⠿⠿⠿⠟⠛⠛⣉⣁⣤⠶⠛⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠛⠲⠶⠶⠶⠤⠤⢤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⠤⠤⠶⠶⠶⠒⠛⠛⠛⠛⠛⠛⠓⠚⠚⠛⠛⠛⠋⠉⠁⠀⠀⠀⠀⠀"""

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW": "\033[1;96m",
    "INFO": "\033[0;37m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
GREEN = "\033[92m"

# port -> (service, severity when exposed to wide/any source)
RISKY_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("FTP (cleartext)", "HIGH"),
    22: ("SSH", "MEDIUM"),
    23: ("Telnet (cleartext)", "CRITICAL"),
    69: ("TFTP", "HIGH"),
    111: ("rpcbind", "HIGH"),
    135: ("MS-RPC", "CRITICAL"),
    139: ("NetBIOS/SMB", "CRITICAL"),
    161: ("SNMP", "MEDIUM"),
    445: ("SMB", "CRITICAL"),
    512: ("rexec", "CRITICAL"),
    513: ("rlogin", "CRITICAL"),
    514: ("rsh/syslog", "HIGH"),
    1433: ("MS SQL Server", "HIGH"),
    1521: ("Oracle DB", "HIGH"),
    2049: ("NFS", "HIGH"),
    2375: ("Docker API (unauthenticated)", "CRITICAL"),
    3306: ("MySQL/MariaDB", "HIGH"),
    3389: ("RDP", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    5900: ("VNC", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
    11211: ("Memcached", "HIGH"),
    27017: ("MongoDB", "HIGH"),
}

Ports = List[Tuple[int, int]]
ANY_PORTS: Ports = [(0, 65535)]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    idx: int
    chain: str
    name: str
    action: str                      # allow | deny
    proto: str                       # any | tcp | udp | icmp | ...
    src: Optional[ipaddress._BaseNetwork]
    dst: Optional[ipaddress._BaseNetwork]
    sports: Ports
    dports: Ports
    enabled: bool = True
    log: bool = False
    complex: bool = False            # uses features we cannot reason about (negation, etc.)
    raw: str = ""

    def label(self) -> str:
        return f"#{self.idx}" + (f" [{self.name}]" if self.name else "")

    def summary(self) -> str:
        return (f"{self.action.upper()} {self.proto} {fmt_net(self.src)} -> {fmt_net(self.dst)} "
                f"dport {fmt_ports(self.dports)}")


@dataclass
class Finding:
    severity: str
    category: str
    rules: List[int]
    message: str
    recommendation: str


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def fmt_net(n) -> str:
    return "any" if n is None else str(n)


def fmt_ports(p: Ports) -> str:
    if p == ANY_PORTS:
        return "any"
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in p)


def parse_net(s) -> Optional[ipaddress._BaseNetwork]:
    s = str(s or "").strip().lower()
    if s in ("", "any", "*", "all", "0.0.0.0/0", "::/0"):
        return None
    return ipaddress.ip_network(s, strict=False)


def parse_ports(s) -> Ports:
    s = str(s if s is not None else "").strip().lower()
    if s in ("", "any", "*", "all"):
        return list(ANY_PORTS)
    out: Ports = []
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        sep = "-" if "-" in part else (":" if ":" in part else None)
        if sep:
            a, b = part.split(sep, 1)
            lo = int(a) if a else 0
            hi = int(b) if b else 65535
        else:
            lo = hi = int(part)
        if lo > hi or lo < 0 or hi > 65535:
            raise ValueError(f"invalid port range '{part}'")
        out.append((lo, hi))
    return out or list(ANY_PORTS)


def parse_action(s) -> str:
    s = str(s).strip().lower()
    if s in ("allow", "accept", "permit", "pass", "allowed"):
        return "allow"
    if s in ("deny", "drop", "reject", "block", "denied"):
        return "deny"
    raise ValueError(f"unknown action '{s}'")


def parse_bool(s, default=True) -> bool:
    if isinstance(s, bool):
        return s
    if s is None or str(s).strip() == "":
        return default
    return str(s).strip().lower() in ("1", "true", "yes", "y", "on", "enabled")


# --------------------------------------------------------------------------- #
# Rule comparison logic
# --------------------------------------------------------------------------- #
def net_covers(a, b) -> bool:
    if a is None:
        return True
    if b is None:
        return False
    return a.version == b.version and b.subnet_of(a)


def net_overlaps(a, b) -> bool:
    if a is None or b is None:
        return True
    return a.version == b.version and a.overlaps(b)


def ports_cover(a: Ports, b: Ports) -> bool:
    return all(any(x[0] <= y[0] and y[1] <= x[1] for x in a) for y in b)


def ports_overlap(a: Ports, b: Ports) -> bool:
    return any(x[0] <= y[1] and y[0] <= x[1] for x in a for y in b)


def proto_covers(a: str, b: str) -> bool:
    return a == "any" or a == b


def proto_overlaps(a: str, b: str) -> bool:
    return a == "any" or b == "any" or a == b


def rule_covers(a: Rule, b: Rule) -> bool:
    """True if every packet matching b also matches a."""
    return (proto_covers(a.proto, b.proto) and net_covers(a.src, b.src)
            and net_covers(a.dst, b.dst) and ports_cover(a.sports, b.sports)
            and ports_cover(a.dports, b.dports))


def rule_overlaps(a: Rule, b: Rule) -> bool:
    return (proto_overlaps(a.proto, b.proto) and net_overlaps(a.src, b.src)
            and net_overlaps(a.dst, b.dst) and ports_overlap(a.sports, b.sports)
            and ports_overlap(a.dports, b.dports))


def is_wide(n) -> bool:
    """Source considered 'internet-exposed': any, or a very large prefix."""
    if n is None:
        return True
    return n.prefixlen <= (8 if n.version == 4 else 16)


def is_catch_all(r: Rule) -> bool:
    return (r.proto == "any" and r.src is None and r.dst is None
            and r.sports == ANY_PORTS and r.dports == ANY_PORTS)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def rule_from_dict(idx: int, d: dict) -> Rule:
    g = lambda *keys: next((d[k] for k in keys if k in d and d[k] is not None), None)
    proto = str(g("protocol", "proto") or "any").strip().lower()
    if proto in ("*", "all", ""):
        proto = "any"
    return Rule(
        idx=idx,
        chain=str(g("chain", "direction", "zone") or "default"),
        name=str(g("name", "description", "comment") or ""),
        action=parse_action(g("action", "target")),
        proto=proto,
        src=parse_net(g("source", "src")),
        dst=parse_net(g("destination", "dst")),
        sports=parse_ports(g("sport", "src_port", "source_port")),
        dports=parse_ports(g("dport", "dst_port", "port", "destination_port")),
        enabled=parse_bool(g("enabled"), True),
        log=parse_bool(g("log", "logging"), False),
        raw=json.dumps({k: (v if isinstance(v, (str, int, float, bool)) else str(v))
                        for k, v in d.items()}),
    )


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    policies = {}
    if isinstance(data, dict):
        policies = {k: parse_action(v) for k, v in (data.get("policies") or {}).items()}
        data = data.get("rules", [])
    return [rule_from_dict(i, d) for i, d in enumerate(data, 1)], policies, []


def load_csv(path: str):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [rule_from_dict(i, {k.strip().lower(): v for k, v in r.items() if k})
            for i, r in enumerate(rows, 1)], {}, []


def load_iptables(path: str):
    rules: List[Rule] = []
    policies: Dict[str, str] = {}
    warnings: List[str] = []
    idx = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if line.startswith(":"):                       # :INPUT DROP [0:0]
                parts = line[1:].split()
                if len(parts) >= 2 and parts[1] in ("ACCEPT", "DROP", "REJECT"):
                    policies[parts[0]] = parse_action(parts[1])
                continue
            if not line.startswith("-A "):
                continue
            try:
                toks = shlex.split(line)
            except ValueError:
                warnings.append(f"line {lineno}: could not tokenise, skipped")
                continue
            chain = toks[1]
            f = dict(chain=chain, proto="any", src=None, dst=None, sport=None,
                     dport=None, comment="", target=None, log=False)
            neg = False
            i = 2
            while i < len(toks):
                t = toks[i]
                nxt = toks[i + 1] if i + 1 < len(toks) else ""
                if t == "!":
                    neg = True
                    i += 1
                    continue
                if t in ("-p", "--protocol"):
                    f["proto"] = nxt.lower(); i += 2
                elif t in ("-s", "--source"):
                    f["src"] = nxt; i += 2
                elif t in ("-d", "--destination"):
                    f["dst"] = nxt; i += 2
                elif t in ("--sport", "--sports", "--source-port", "--source-ports"):
                    f["sport"] = nxt; i += 2
                elif t in ("--dport", "--dports", "--destination-port", "--destination-ports"):
                    f["dport"] = nxt; i += 2
                elif t == "--comment":
                    f["comment"] = nxt; i += 2
                elif t in ("-j", "-g", "--jump"):
                    f["target"] = nxt; i += 2
                else:
                    i += 1
            if f["target"] not in ("ACCEPT", "DROP", "REJECT"):
                continue                                     # non-terminal / custom chain
            idx += 1
            try:
                r = rule_from_dict(idx, {
                    "chain": chain, "name": f["comment"], "action": f["target"],
                    "protocol": f["proto"], "source": f["src"], "destination": f["dst"],
                    "sport": (f["sport"] or "").replace(":", "-"),
                    "dport": (f["dport"] or "").replace(":", "-"),
                })
            except Exception as exc:  # noqa: BLE001
                idx -= 1
                warnings.append(f"line {lineno}: {exc}, skipped")
                continue
            r.raw = line
            if neg:
                r.complex = True
                warnings.append(f"line {lineno}: rule uses negation ('!') - excluded from overlap analysis")
            rules.append(r)
    return rules, policies, warnings


def detect_format(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return "json"
    if ext == ".csv":
        return "csv"
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096).lstrip()
    if head.startswith(("{", "[")):
        return "json"
    if "-A " in head or head.startswith("*filter") or "# Generated by" in head:
        return "iptables"
    return "csv"


# --------------------------------------------------------------------------- #
# Analysis engine
# --------------------------------------------------------------------------- #
def analyze(rules: List[Rule], policies: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    add = lambda sev, cat, rs, msg, rec: findings.append(Finding(sev, cat, rs, msg, rec))

    for r in rules:
        if not r.enabled:
            add("INFO", "Disabled rule", [r.idx],
                f"Rule {r.label()} is disabled.",
                "Remove stale disabled rules to keep the policy auditable.")

    active = [r for r in rules if r.enabled]
    chains: Dict[str, List[Rule]] = {}
    for r in active:
        chains.setdefault(r.chain, []).append(r)

    for chain, rs in chains.items():
        analyzable = [r for r in rs if not r.complex]

        # ---- shadowing / redundancy / conflicts ---------------------------- #
        for j, rj in enumerate(analyzable):
            hit = False
            for ri in analyzable[:j]:
                if rule_covers(ri, rj):
                    if ri.action != rj.action:
                        add("HIGH", "Shadowed rule", [ri.idx, rj.idx],
                            f"[{chain}] {rj.label()} ({rj.summary()}) can never match: "
                            f"{ri.label()} ({ri.summary()}) already handles all of its traffic "
                            f"with the opposite action.",
                            f"Move {rj.label()} above {ri.label()} or delete it if unintended.")
                    else:
                        add("MEDIUM", "Redundant rule", [ri.idx, rj.idx],
                            f"[{chain}] {rj.label()} ({rj.summary()}) is redundant: "
                            f"{ri.label()} already {ri.action}s the same traffic.",
                            f"Remove {rj.label()} to shrink and simplify the rule base.")
                    hit = True
                    break
            if hit:
                continue
            for ri in analyzable[:j]:
                if ri.action != rj.action and rule_overlaps(ri, rj):
                    add("LOW", "Conflicting overlap", [ri.idx, rj.idx],
                        f"[{chain}] {ri.label()} ({ri.action}) and {rj.label()} ({rj.action}) "
                        f"partially overlap; outcome depends on rule order.",
                        "Confirm the ordering is intentional and document it, or make the "
                        "matches mutually exclusive.")

        # ---- permissive / risky exposure ----------------------------------- #
        for r in analyzable:
            if r.action != "allow":
                continue
            if is_catch_all(r):
                add("CRITICAL", "Any-any allow", [r.idx],
                    f"[{chain}] {r.label()} allows ALL traffic from any source to any destination.",
                    "Replace with explicit allow rules for required flows only.")
                continue
            if r.src is None and r.dports == ANY_PORTS:
                add("HIGH", "Overly permissive", [r.idx],
                    f"[{chain}] {r.label()} allows any source to reach ALL ports "
                    f"({r.proto}) on {fmt_net(r.dst)}.",
                    "Restrict to the specific ports/services that need exposure.")
            elif r.src is None and any((b - a) > 1000 for a, b in r.dports):
                add("MEDIUM", "Wide port range", [r.idx],
                    f"[{chain}] {r.label()} exposes a large port range ({fmt_ports(r.dports)}) "
                    f"to any source.",
                    "Narrow the range to only the required ports.")
            if r.proto in ("any", "tcp", "udp") and is_wide(r.src):
                for port, (svc, sev) in RISKY_PORTS.items():
                    for a, b in r.dports:
                        if a <= port <= b and (b - a) <= 1000:
                            add(sev, "Risky service exposed", [r.idx],
                                f"[{chain}] {r.label()} exposes {svc} (port {port}) to "
                                f"{fmt_net(r.src)}.",
                                f"Restrict {svc} to trusted management networks / VPN, "
                                f"or block it from untrusted sources.")
                            break

        # ---- default deny + logging --------------------------------------- #
        policy = policies.get(chain)
        last = rs[-1]
        has_final_deny = last.action == "deny" and is_catch_all(last)
        if policy != "deny" and not has_final_deny:
            add("MEDIUM", "No default deny", [last.idx],
                f"[{chain}] Chain has no default-deny policy and no final catch-all deny rule.",
                "Set the chain policy to DROP/deny, or append an explicit 'deny any any' rule.")
        if has_final_deny and not last.log:
            add("LOW", "No logging on catch-all deny", [last.idx],
                f"[{chain}] Final deny {last.label()} does not log dropped traffic.",
                "Enable logging (rate-limited) on the catch-all deny for visibility.")

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.rules))
    return findings


def risk_score(findings: List[Finding]) -> Tuple[int, str]:
    score = min(100, sum(WEIGHTS[f.severity] for f in findings))
    grade = "A" if score < 10 else "B" if score < 30 else "C" if score < 55 else "D" if score < 80 else "F"
    return score, grade


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def banner(color: bool):
    c = (lambda s, code: f"{code}{s}{RESET}") if color else (lambda s, code: s)
    print(c(BANNER_ART, CYAN))
    line = "=" * 64
    print(c(line, CYAN))
    print(c(f"  FIREWALL RULE ANALYZER  v{VERSION}", BOLD))
    print(c(f"  Coded by : {AUTHOR}", GREEN))
    print(c(f"  Role     : {TITLE}", GREEN))
    print(c(line, CYAN))
    print()


def print_report(path, fmt, rules, findings, warnings, min_sev, color):
    c = (lambda s, code: f"{code}{s}{RESET}") if color else (lambda s, code: s)
    score, grade = risk_score(findings)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    order = {s: i for i, s in enumerate(SEVERITIES)}

    print(c("Target     :", BOLD), path, f"({fmt})")
    print(c("Rules      :", BOLD),
          f"{len(rules)} total, {sum(1 for r in rules if r.enabled)} enabled")
    for w in warnings:
        print(c(f"  ! {w}", DIM))
    print()

    shown = [f for f in findings if order[f.severity] <= order[min_sev]]
    if not shown:
        print(c("No findings at or above the selected severity. Nice and tidy.", GREEN))
    for n, f in enumerate(shown, 1):
        tag = c(f" {f.severity} ", COLORS[f.severity])
        print(f"{c(f'{n:>2}.', BOLD)} {tag} {c(f.category, BOLD)}  (rules: {', '.join('#' + str(i) for i in f.rules)})")
        print(f"      {f.message}")
        print(c(f"      Fix: {f.recommendation}", DIM))
        print()

    print(c("-" * 64, CYAN))
    print(c("SUMMARY", BOLD))
    print("  " + "  ".join(c(f" {s}: {counts[s]} ", COLORS[s]) for s in SEVERITIES))
    print(f"  Risk score: {c(str(score) + '/100', BOLD)}   Grade: {c(grade, BOLD)}")
    print(c("-" * 64, CYAN))


def write_sample(path: str):
    sample = {
        "policies": {},
        "rules": [
            {"chain": "INPUT", "name": "Allow web", "action": "allow", "protocol": "tcp",
             "source": "any", "destination": "10.0.0.10", "dport": "80,443", "log": False},
            {"chain": "INPUT", "name": "Allow SSH from admin net", "action": "allow", "protocol": "tcp",
             "source": "192.168.50.0/24", "destination": "10.0.0.0/24", "dport": "22"},
            {"chain": "INPUT", "name": "RDP from anywhere", "action": "allow", "protocol": "tcp",
             "source": "any", "destination": "10.0.0.20", "dport": "3389"},
            {"chain": "INPUT", "name": "Telnet legacy", "action": "allow", "protocol": "tcp",
             "source": "any", "destination": "10.0.0.30", "dport": "23"},
            {"chain": "INPUT", "name": "Allow all from LAN", "action": "allow", "protocol": "any",
             "source": "192.168.0.0/16", "destination": "any", "dport": "any"},
            {"chain": "INPUT", "name": "Block guest SSH", "action": "deny", "protocol": "tcp",
             "source": "192.168.50.0/24", "destination": "10.0.0.0/24", "dport": "22"},
            {"chain": "INPUT", "name": "Allow HTTPS (dup)", "action": "allow", "protocol": "tcp",
             "source": "any", "destination": "10.0.0.10", "dport": "443"},
            {"chain": "INPUT", "name": "Open high ports", "action": "allow", "protocol": "tcp",
             "source": "any", "destination": "10.0.0.40", "dport": "1024-65535"},
            {"chain": "INPUT", "name": "Old rule", "action": "allow", "protocol": "tcp",
             "source": "172.16.0.0/12", "destination": "10.0.0.50", "dport": "8080", "enabled": False},
            {"chain": "FORWARD", "name": "Allow everything", "action": "allow", "protocol": "any",
             "source": "any", "destination": "any", "dport": "any"},
            {"chain": "FORWARD", "name": "Block SMB", "action": "deny", "protocol": "tcp",
             "source": "any", "destination": "any", "dport": "445"},
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sample, fh, indent=2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Firewall Rule Analyzer - by Mr Sabaz Ali Khan (Cyber Security Engineer)")
    ap.add_argument("file", nargs="?", help="rules file (JSON, CSV or iptables-save output)")
    ap.add_argument("--format", choices=["auto", "json", "csv", "iptables"], default="auto")
    ap.add_argument("--json-out", metavar="FILE", help="also write findings as JSON")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                    help="hide findings below this severity")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--sample", nargs="?", const="sample_rules.json", metavar="FILE",
                    help="write a sample rules file (default: sample_rules.json) and exit")
    args = ap.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color and os.name != "nt" or \
        (os.name == "nt" and not args.no_color and sys.stdout.isatty())
    if os.name == "nt":
        os.system("")  # enable ANSI escapes on modern Windows terminals
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    if not args.no_banner:
        banner(color)

    if args.sample:
        write_sample(args.sample)
        print(f"Sample rules written to {args.sample}")
        return 0
    if not args.file:
        ap.print_help()
        return 0
    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    fmt = detect_format(args.file) if args.format == "auto" else args.format
    try:
        loader = {"json": load_json, "csv": load_csv, "iptables": load_iptables}[fmt]
        rules, policies, warnings = loader(args.file)
    except Exception as exc:  # noqa: BLE001
        print(f"Error parsing {args.file} as {fmt}: {exc}", file=sys.stderr)
        return 2

    findings = analyze(rules, policies)
    print_report(args.file, fmt, rules, findings, warnings, args.min_severity, color)

    if args.json_out:
        score, grade = risk_score(findings)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({
                "tool": "Firewall Rule Analyzer", "version": VERSION, "author": AUTHOR,
                "source": args.file, "format": fmt, "rule_count": len(rules),
                "risk_score": score, "grade": grade,
                "findings": [asdict(f) for f in findings],
            }, fh, indent=2)
        print(f"JSON report written to {args.json_out}")

    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
