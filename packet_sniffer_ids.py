#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Packet Sniffer + Intrusion Detector
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Requirements:
    pip install scapy
    Run with root / Administrator privileges (Npcap required on Windows).

Usage examples:
    sudo python3 packet_sniffer_ids.py -i eth0
    sudo python3 packet_sniffer_ids.py -i wlan0 -f "tcp or udp" --pcap capture.pcap
    sudo python3 packet_sniffer_ids.py --blacklist bad_ips.txt --quiet
    python3 packet_sniffer_ids.py --read capture.pcap        (offline analysis)

LEGAL: Use only on networks you own or are explicitly authorized to monitor.
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import (
        sniff, rdpcap, PcapWriter, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, conf
    )
except ImportError:
    print("[!] Scapy is required.  Install it with:  pip install scapy")
    sys.exit(1)

BANNER = r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⠀⠀⢀⣠⣤⣶⣶⣶⣶⣶⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⡔⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢟⣫⣯⣷⣾⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣷⡙⢿⣿⣿⣿⣿⣿⣿⡿⢋⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣙⠿⠿⠿⢟⣫⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⢹⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⡏⠉⠙⢿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⡿⡍⠳⣄⡀⢀⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⢿⡄⠸⡿⢄⠛⣘⢠⣼⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀
⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡞⣼⡻⡄⠳⡤⠽⠾⠿⠿⠿⢛⣻⣿⣿⣿⣷⡀⠀⠀⠀
⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣄⠙⢶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀
⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠉⢉⣁⣀⣀⣀⣀⣀⣉⡉⠙⠛⠻⢿⣿⣿⣿⣿⣿⣯⣻⣍⡲⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⢀⡀⣶⣤⣌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⣁⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣈⠛⢿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⡿⠟⠛⠛⠁⠀⠀
⣰⣿⣿⣿⣿⣿⣿⣿⣝⢿⣿⣿⣿⣿⣿⣿⣟⣡⣶⠿⢛⣛⣉⣭⣭⣤⣤⡴⠶⠶⠶⠶⢲⣴⣤⠭⠭⡭⣟⠻⠦⣝⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢉⣀⣠⣶⣿⣆⠀⠀
⠹⣿⣿⣿⣿⣿⣿⣙⠻⣿⣮⣛⠿⣿⣿⣿⣫⣵⡶⠟⣛⣋⣭⣭⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣮⣽⣿⣿⣿⠿⠟⠛⠉⢀⣴⣿⣿⣿⣿⣿⣿⣶⡀
⠀⠈⠙⠋⠁⠀⠈⠉⠛⠳⣭⣛⢷⣦⣸⣿⣯⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣿⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⡟⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⠿⠿⢿⣹⣿⣧⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⡏⣀⣴⣾⣿⣿⠿⠛⠉⠀⠀⠀⠈⠛⠛⠉⠀
⠀⠀⠀⠀⢀⣴⠿⠛⠋⠁⠀⠀⠀⢀⣯⢿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⠣⣟⡻⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⢀⣀⣴⣾⣿⠈⡿⣿⠃⠀⠀⠀⠈⠉⠛⠻⠿⣿⣿⣿⣿⣿⠿⠛⠉⠉⠀⠈⠉⠛⣿⣽⡟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣠⣤⣶⣾⣿⣿⣿⣿⣿⣀⣼⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣹⡟⣻⣿⡃⠀⠀⠀⠀⠀⠀⠀⠀⢹⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⢹⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⣰⣿⢣⡇⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠟⠋⠙⠛⠻⣿⣿⣿⣿⣿⠏⠀⠈⢿⣿⣿⣿⣦⣄⣀⣀⣀⣠⣴⣿⣏⡞⢻⣸⣿⣷⣄⠀⠀⣀⣤⠴⣾⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⠃⠀⠀⠀⠈⢿⣿⣵⣾⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣶⠾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣏⠀⠀⠀⠀⠀⣀⣼⣿⡛⢿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠟⣡⣾⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⢠⣶⣿⣿⣯⣿⡇⠀⢹⣿⣿⣿⣿⣷⣤⣤⣦⣶⣿⣿⣿⣿⣿⡇⠀⣿⣿⢸⣿⣶⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣄⣠⣴⣾⣿⣟⣿⠟⠁⣿⡇⠀⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡇⢀⣿⣿⠙⢮⣛⠿⣷⣦⣄⣀⣀⣀⣠⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⣶⣶⣾⣿⣿⡿⣛⣽⠞⠋⠀⠀⠀⣿⣷⠀⣍⠇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠉⡄⣸⣿⡿⠀⠀⠈⠙⠮⣟⠿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣹⣿⣿⣿⢵⡿⠋⠀⠀⠀⠀⠀⠀⢿⣿⣦⣿⡷⣄⠙⠿⣿⢹⣿⣿⢼⡿⠋⣡⣶⣳⣿⣿⣿⠃⠀⠀⠀⠀⠀⠈⠿⠬⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣷⣻⢿⣶⣬⣈⣉⣉⣤⣴⣿⣻⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⡿⠇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⡇⣿⣇⣿⢹⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

CREDIT = "Network Packet Sniffer + Intrusion Detector  |  coded by Mr Sabaz Ali Khan"

# ----------------------------------------------------------------------------
# Colours
# ----------------------------------------------------------------------------
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    MAG = "\033[95m"
    DIM = "\033[2m"
    BLD = "\033[1m"
    END = "\033[0m"


SEVERITY_COLOR = {"LOW": C.CYN, "MEDIUM": C.YEL, "HIGH": C.RED, "CRITICAL": C.MAG}

# TCP flag bit masks
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 80: "HTTP"}
SUSPICIOUS_PORTS = {4444: "Metasploit default", 31337: "Back Orifice", 1337: "Common backdoor",
                    6667: "IRC (possible botnet C2)", 12345: "NetBus", 5555: "ADB / RAT"}


def print_banner():
    print(C.CYN + BANNER + C.END)
    print(C.GRN + C.BLD + "=" * 78 + C.END)
    print(C.GRN + C.BLD + CREDIT.center(78) + C.END)
    print(C.GRN + C.BLD + "=" * 78 + C.END + "\n")


# ----------------------------------------------------------------------------
# Intrusion Detection Engine
# ----------------------------------------------------------------------------
class IDSEngine:
    def __init__(self, args):
        self.window = args.window
        self.t_portscan = args.portscan_threshold
        self.t_syn = args.syn_threshold
        self.t_icmp = args.icmp_threshold
        self.t_udp = args.udp_threshold
        self.t_dns_len = args.dns_len
        self.cooldown = args.cooldown
        self.log_path = args.log
        self.quiet = args.quiet

        self.blacklist = set()
        if args.blacklist:
            self._load_blacklist(args.blacklist)

        self.syn_times = defaultdict(deque)          # src -> deque[ts]
        self.scan_ports = defaultdict(deque)         # src -> deque[(ts, dst, dport)]
        self.icmp_times = defaultdict(deque)
        self.udp_times = defaultdict(deque)
        self.arp_table = {}                          # ip -> mac
        self.last_alert = {}                         # (type, key) -> ts
        self.cleartext_seen = set()

        self.alerts = []
        self.stats = defaultdict(int)
        self.talkers = defaultdict(int)

    def _load_blacklist(self, path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.blacklist.add(line)
            print(f"{C.GRN}[+] Loaded {len(self.blacklist)} blacklisted IPs{C.END}")
        except OSError as exc:
            print(f"{C.RED}[!] Cannot read blacklist: {exc}{C.END}")

    # -- helpers --------------------------------------------------------
    @staticmethod
    def _trim(dq, now, window, key=lambda x: x):
        while dq and now - key(dq[0]) > window:
            dq.popleft()

    def alert(self, kind, severity, src, detail, dst=None):
        now = time.time()
        k = (kind, src)
        if now - self.last_alert.get(k, 0) < self.cooldown:
            return
        self.last_alert[k] = now

        record = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "type": kind,
            "severity": severity,
            "src": src,
            "dst": dst,
            "detail": detail,
        }
        self.alerts.append(record)
        self.stats["alerts"] += 1

        col = SEVERITY_COLOR.get(severity, C.YEL)
        print(f"{col}{C.BLD}[ALERT][{severity}] {kind}{C.END}{col} "
              f"src={src} dst={dst or '-'} :: {detail}{C.END}")

        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
            except OSError:
                pass

    # -- main per-packet analysis --------------------------------------
    def analyze(self, pkt):
        now = time.time()
        self.stats["packets"] += 1

        # ARP spoofing ---------------------------------------------------
        if pkt.haslayer(ARP):
            self.stats["ARP"] += 1
            arp = pkt[ARP]
            if arp.op == 2:  # is-at (reply)
                known = self.arp_table.get(arp.psrc)
                if known and known != arp.hwsrc:
                    self.alert("ARP Spoofing", "CRITICAL", arp.psrc,
                               f"IP {arp.psrc} changed MAC {known} -> {arp.hwsrc} (possible MITM)")
                self.arp_table[arp.psrc] = arp.hwsrc
            return

        if pkt.haslayer(IP):
            ip = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
        else:
            return

        src, dst = ip.src, ip.dst
        self.talkers[src] += 1

        # Blacklist ------------------------------------------------------
        if src in self.blacklist or dst in self.blacklist:
            bad = src if src in self.blacklist else dst
            self.alert("Blacklisted IP", "HIGH", src, f"Traffic involving blacklisted host {bad}", dst)

        # TCP ------------------------------------------------------------
        if pkt.haslayer(TCP):
            self.stats["TCP"] += 1
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            dport = tcp.dport

            # Stealth scan signatures
            if flags == 0:
                self.alert("NULL Scan", "HIGH", src, f"TCP packet with no flags to port {dport}", dst)
            elif flags & (FIN | PSH | URG) == (FIN | PSH | URG):
                self.alert("XMAS Scan", "HIGH", src, f"FIN+PSH+URG packet to port {dport}", dst)
            elif flags == FIN:
                self.alert("FIN Scan", "MEDIUM", src, f"Lone FIN packet to port {dport}", dst)

            # SYN tracking (SYN without ACK)
            if flags & SYN and not flags & ACK:
                dq = self.syn_times[src]
                dq.append(now)
                self._trim(dq, now, self.window)
                if len(dq) >= self.t_syn:
                    self.alert("SYN Flood", "CRITICAL", src,
                               f"{len(dq)} SYN packets in {self.window}s", dst)

                sp = self.scan_ports[src]
                sp.append((now, dst, dport))
                self._trim(sp, now, self.window, key=lambda x: x[0])
                distinct = {(d, p) for _, d, p in sp}
                if len({p for _, p in distinct}) >= self.t_portscan:
                    self.alert("Port Scan", "HIGH", src,
                               f"{len({p for _, p in distinct})} distinct ports probed in {self.window}s", dst)

            # Suspicious / backdoor ports
            for port in (tcp.sport, tcp.dport):
                if port in SUSPICIOUS_PORTS:
                    self.alert("Suspicious Port", "MEDIUM", src,
                               f"Traffic on port {port} ({SUSPICIOUS_PORTS[port]})", dst)

            # Cleartext protocols
            if dport in CLEARTEXT_PORTS and dport != 80 and (src, dst, dport) not in self.cleartext_seen:
                self.cleartext_seen.add((src, dst, dport))
                self.alert("Cleartext Protocol", "LOW", src,
                           f"{CLEARTEXT_PORTS[dport]} (port {dport}) - unencrypted traffic", dst)

            # Cleartext credential keywords in payload
            if pkt.haslayer(Raw) and dport in (21, 23, 80, 110, 143):
                payload = bytes(pkt[Raw].load)[:512].lower()
                for kw in (b"password=", b"passwd=", b"pass ", b"authorization: basic"):
                    if kw in payload:
                        self.alert("Cleartext Credentials", "HIGH", src,
                                   f"Possible credentials sent unencrypted to port {dport}", dst)
                        break

        # UDP / DNS ------------------------------------------------------
        elif pkt.haslayer(UDP):
            self.stats["UDP"] += 1
            dq = self.udp_times[src]
            dq.append(now)
            self._trim(dq, now, self.window)
            if len(dq) >= self.t_udp:
                self.alert("UDP Flood", "HIGH", src, f"{len(dq)} UDP packets in {self.window}s", dst)

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                self.stats["DNS"] += 1
                try:
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = ""
                if len(qname) >= self.t_dns_len:
                    self.alert("DNS Tunneling?", "MEDIUM", src,
                               f"Very long DNS query ({len(qname)} chars): {qname[:60]}...", dst)

        # ICMP -----------------------------------------------------------
        elif pkt.haslayer(ICMP):
            self.stats["ICMP"] += 1
            if pkt[ICMP].type == 8:  # echo request
                dq = self.icmp_times[src]
                dq.append(now)
                self._trim(dq, now, self.window)
                if len(dq) >= self.t_icmp:
                    self.alert("ICMP Flood / Ping Sweep", "HIGH", src,
                               f"{len(dq)} echo requests in {self.window}s", dst)

    # -- reporting ------------------------------------------------------
    def summary(self):
        print("\n" + C.BLD + "=" * 78 + C.END)
        print(C.BLD + "SESSION SUMMARY".center(78) + C.END)
        print(C.BLD + "=" * 78 + C.END)
        for k in ("packets", "TCP", "UDP", "ICMP", "ARP", "DNS", "alerts"):
            print(f"  {k:<10}: {self.stats.get(k, 0)}")
        if self.talkers:
            print("\n  Top talkers:")
            for ip, cnt in sorted(self.talkers.items(), key=lambda x: -x[1])[:5]:
                print(f"    {ip:<40} {cnt} pkts")
        if self.alerts:
            by_type = defaultdict(int)
            for a in self.alerts:
                by_type[a["type"]] += 1
            print("\n  Alerts by type:")
            for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"    {t:<28} {n}")
        print(C.BLD + "=" * 78 + C.END)


# ----------------------------------------------------------------------------
# Packet summary line
# ----------------------------------------------------------------------------
def summarize(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        op = "who-has" if a.op == 1 else "is-at"
        return f"{ts} ARP  {op} {a.pdst if a.op == 1 else a.psrc} ({a.hwsrc})"
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return f"{ts} {pkt.summary()}"
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return f"{ts} TCP  {ip.src}:{t.sport} -> {ip.dst}:{t.dport} [{t.flags}] len={len(pkt)}"
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        extra = ""
        if pkt.haslayer(DNSQR):
            extra = f" DNS? {pkt[DNSQR].qname.decode(errors='ignore')}"
        return f"{ts} UDP  {ip.src}:{u.sport} -> {ip.dst}:{u.dport} len={len(pkt)}{extra}"
    if pkt.haslayer(ICMP):
        return f"{ts} ICMP {ip.src} -> {ip.dst} type={pkt[ICMP].type}"
    return f"{ts} IP   {ip.src} -> {ip.dst} proto={ip.proto}"


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Network Packet Sniffer + Intrusion Detector - coded by Mr Sabaz Ali Khan")
    p.add_argument("-i", "--iface", help="Interface to sniff on (default: scapy default)")
    p.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    p.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = unlimited)")
    p.add_argument("-t", "--timeout", type=int, default=None, help="Stop after N seconds")
    p.add_argument("--read", metavar="PCAP", help="Analyze an existing pcap file instead of live sniffing")
    p.add_argument("--pcap", metavar="FILE", help="Save captured packets to a pcap file")
    p.add_argument("--log", default="ids_alerts.jsonl", help="JSON-lines alert log (default: ids_alerts.jsonl)")
    p.add_argument("--blacklist", metavar="FILE", help="File with one malicious IP per line")
    p.add_argument("--quiet", action="store_true", help="Only show alerts, hide per-packet lines")
    p.add_argument("--window", type=int, default=10, help="Detection window in seconds (default 10)")
    p.add_argument("--portscan-threshold", type=int, default=15, help="Distinct ports/window = scan (default 15)")
    p.add_argument("--syn-threshold", type=int, default=100, help="SYNs/window = flood (default 100)")
    p.add_argument("--icmp-threshold", type=int, default=50, help="ICMP echo/window = flood (default 50)")
    p.add_argument("--udp-threshold", type=int, default=200, help="UDP pkts/window = flood (default 200)")
    p.add_argument("--dns-len", type=int, default=60, help="DNS query length considered suspicious (default 60)")
    p.add_argument("--cooldown", type=int, default=30, help="Seconds before repeating the same alert (default 30)")
    return p.parse_args()


def is_admin():
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def main():
    args = parse_args()
    print_banner()

    if not args.read and not is_admin():
        print(f"{C.RED}[!] Live sniffing needs root/Administrator privileges. Re-run with sudo.{C.END}")
        sys.exit(1)

    ids = IDSEngine(args)
    writer = PcapWriter(args.pcap, append=True, sync=True) if args.pcap else None

    def handle(pkt):
        if writer:
            writer.write(pkt)
        if not args.quiet:
            print(C.DIM + summarize(pkt) + C.END)
        ids.analyze(pkt)

    try:
        if args.read:
            print(f"{C.GRN}[+] Analyzing {args.read} ...{C.END}\n")
            for pkt in rdpcap(args.read):
                handle(pkt)
        else:
            iface = args.iface or conf.iface
            print(f"{C.GRN}[+] Sniffing on {iface}  filter='{args.filter or 'none'}'  "
                  f"(Ctrl+C to stop){C.END}\n")
            sniff(iface=args.iface, filter=args.filter or None, prn=handle, store=False,
                  count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{C.YEL}[!] Stopped by user{C.END}")
    except PermissionError:
        print(f"{C.RED}[!] Permission denied. Run as root/Administrator.{C.END}")
    except Exception as exc:
        print(f"{C.RED}[!] Error: {exc}{C.END}")
    finally:
        if writer:
            writer.close()
        ids.summary()
        print(f"\n{C.GRN}{CREDIT}{C.END}")


if __name__ == "__main__":
    main()
