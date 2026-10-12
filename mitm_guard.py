#!/usr/bin/env python3
"""
MITM Guard - Man-in-the-Middle Detection & Prevention Tool
Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan

For defensive use on networks you own or are authorised to protect.

Features
  scan     One-shot ARP table audit (duplicate MACs, gateway MAC baseline)
  monitor  Live sniffing: ARP spoofing, Ethernet/ARP mismatch, ARP floods,
           conflicting DNS replies (DNS spoofing / race attacks)
  tls      TLS certificate pinning (trust-on-first-use) + chain validation
  harden   Pin the gateway MAC as a static ARP entry (prevention)

Install:  pip install scapy
Run as admin/root for monitor + harden modes.
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⢠⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣴⣾⢿⣷⣦⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡇⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀
⠸⣿⠀⠀⠈⢻⣷⠰⠇⠀⠀⠀⠀⠀⣷⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠹⣧⠀⣾⢻⡄⠀⢀⣀⡀⢰⣤⢦⡄⢀⡇⠀⠀⢸⡇⠀⠀⠀
⠀⢿⣇⠀⢀⣾⠇⠀⡆⠀⢀⡶⠒⢸⣿⡴⠏⠀⠀⠀⢠⡄⠀⢀⠀⣾⠀⠀⠀⣿⠀⢹⢰⡿⢰⣧⢠⡞⢻⡇⢸⣧⠞⢁⣼⣥⣀⠀⠈⣷⣀⡤⠖
⠀⠈⣿⣿⣿⣁⠀⠀⢻⠀⣿⠀⠀⠀⣿⢧⡀⠀⠀⠀⡿⢧⠿⢾⣴⣇⠀⠀⢸⡟⠀⠘⢿⠁⠈⡟⠸⢧⣼⠟⢠⠉⢷⠀⢸⠀⠀⢀⣰⡿⠋⠀⠀
⠀⠀⢻⡆⠈⠛⢻⣆⠘⠀⠙⠏⠉⠀⠇⠈⢿⡄⠀⠀⠁⠈⠀⠀⠈⠉⠀⠀⢘⠃⠀⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠸⠀⡼⠀⢀⡾⠋⠀⠀⠀⠀
⠀⠀⠘⣧⠀⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀⠀⠈⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀⠀⠀⠘⠇⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠙⠀⠀⠀⠀⠀⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = "MITM Guard  |  Detection & Prevention Tool\n" \
         "Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan"

OS = platform.system()
LOG_FILE = "mitm_guard.log"
PIN_FILE = "tls_pins.json"

RED, YEL, GRN, CYN, RST = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[0m"
if OS == "Windows":
    os.system("")  # enable ANSI colours on Windows 10+

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")


def show_banner():
    print(CYN + BANNER + RST)
    print(GRN + CREDIT + RST + "\n")


def alert(level, title, detail):
    colour = RED if level == "CRITICAL" else YEL
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{colour}[{ts}] [{level}] {title}{RST}\n         {detail}")
    logging.warning("%s | %s | %s", level, title, detail)


def info(msg):
    print(f"{GRN}[+]{RST} {msg}")
    logging.info(msg)


# --------------------------------------------------------------------------
# Helpers: ARP table, gateway, interface
# --------------------------------------------------------------------------
def norm_mac(mac):
    parts = re.split(r"[:-]", mac.lower())
    return ":".join(p.zfill(2) for p in parts)


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""


def get_arp_table():
    out = run(["arp", "-a"])
    pat = re.compile(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?"
                     r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    table = {}
    for ip, mac in pat.findall(out):
        mac = norm_mac(mac)
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith("01:00:5e"):
            continue
        table[ip] = mac
    return table


def get_gateway():
    if OS == "Linux":
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)(?: dev (\S+))?", run(["ip", "route"]))
        return (m.group(1), m.group(2)) if m else (None, None)
    if OS == "Darwin":
        out = run(["route", "-n", "get", "default"])
        g = re.search(r"gateway:\s+(\S+)", out)
        i = re.search(r"interface:\s+(\S+)", out)
        return (g.group(1) if g else None, i.group(1) if i else None)
    if OS == "Windows":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                      run(["route", "print", "0.0.0.0"]))
        return (m.group(1), m.group(2)) if m else (None, None)
    return None, None


def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())


# --------------------------------------------------------------------------
# Prevention
# --------------------------------------------------------------------------
def pin_gateway(ip, mac, iface=None):
    """Create a static ARP entry so forged ARP replies are ignored."""
    if not is_admin():
        alert("WARNING", "Prevention skipped", "Administrator/root rights required.")
        return False
    if OS == "Linux":
        cmd = ["ip", "neigh", "replace", ip, "lladdr", mac, "nud", "permanent"]
        if iface:
            cmd += ["dev", iface]
    elif OS == "Darwin":
        cmd = ["arp", "-s", ip, mac]
    elif OS == "Windows":
        cmd = ["netsh", "interface", "ipv4", "add", "neighbors", iface or "Ethernet", ip,
               mac.replace(":", "-")]
    else:
        return False
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        info(f"Static ARP entry set: {ip} -> {mac}")
        return True
    alert("WARNING", "Could not pin gateway", r.stderr.strip() or r.stdout.strip())
    return False


def block_attacker(mac):
    """Linux only: drop frames from the spoofing MAC."""
    if OS != "Linux" or not is_admin():
        return
    cmd = ["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
    if subprocess.run(cmd, capture_output=True).returncode == 0:
        info(f"Blocked traffic from attacker MAC {mac}")


# --------------------------------------------------------------------------
# Mode: scan
# --------------------------------------------------------------------------
def cmd_scan(_args):
    gw_ip, iface = get_gateway()
    table = get_arp_table()
    info(f"Gateway: {gw_ip}  Interface: {iface}  ARP entries: {len(table)}")
    findings = 0

    by_mac = defaultdict(list)
    for ip, mac in table.items():
        by_mac[mac].append(ip)
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            findings += 1
            sev = "CRITICAL" if gw_ip in ips else "WARNING"
            alert(sev, "Duplicate MAC in ARP table",
                  f"{mac} claims {', '.join(ips)} (possible ARP poisoning)")
    if gw_ip and gw_ip in table:
        info(f"Gateway MAC: {table[gw_ip]}")
    if not findings:
        info("No ARP anomalies found.")


# --------------------------------------------------------------------------
# Mode: monitor
# --------------------------------------------------------------------------
class Monitor:
    def __init__(self, prevent, trusted_gw_mac, iface):
        self.prevent = prevent
        self.gw_ip, auto_iface = get_gateway()
        self.iface = iface or auto_iface
        self.baseline = get_arp_table()
        if trusted_gw_mac:
            self.baseline[self.gw_ip] = norm_mac(trusted_gw_mac)
        self.mac_ips = defaultdict(set)
        self.reply_times = defaultdict(lambda: deque(maxlen=200))
        self.dns_seen = {}
        self.alerted = set()

    def once(self, key, *a):
        if key in self.alerted:
            return
        self.alerted.add(key)
        alert(*a)

    def handle(self, pkt):
        from scapy.all import ARP, DNS, Ether, IP
        try:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                self.handle_arp(pkt, ARP, Ether)
            elif pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                self.handle_dns(pkt, DNS, IP)
        except Exception as exc:
            logging.error("handler error: %s", exc)

    def handle_arp(self, pkt, ARP, Ether):
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()
        now = time.time()

        if pkt.haslayer(Ether) and pkt[Ether].src.lower() != mac:
            self.once(("eth", ip, mac), "CRITICAL", "Ethernet/ARP MAC mismatch",
                      f"Frame from {pkt[Ether].src} claims ARP sender {mac} for {ip}")

        known = self.baseline.get(ip)
        if known is None:
            self.baseline[ip] = mac
        elif known != mac:
            sev = "CRITICAL" if ip == self.gw_ip else "WARNING"
            self.once(("chg", ip, mac), sev, "ARP spoofing detected",
                      f"{ip} changed from {known} to {mac}")
            if ip == self.gw_ip and self.prevent:
                pin_gateway(ip, known, self.iface)
                block_attacker(mac)

        self.mac_ips[mac].add(ip)
        if len(self.mac_ips[mac]) > 1:
            self.once(("dup", mac, tuple(sorted(self.mac_ips[mac]))), "WARNING",
                      "One MAC answering for several IPs",
                      f"{mac} -> {', '.join(sorted(self.mac_ips[mac]))} "
                      "(could be proxy ARP or a poisoner)")

        q = self.reply_times[mac]
        q.append(now)
        recent = [t for t in q if now - t < 10]
        if len(recent) > 30:
            self.once(("flood", mac, int(now // 60)), "WARNING", "ARP reply flood",
                      f"{mac} sent {len(recent)} ARP replies in 10s")

    def handle_dns(self, pkt, DNS, IP):
        dns = pkt[DNS]
        answers = set()
        for i in range(dns.ancount):
            rr = dns.an[i]
            if getattr(rr, "type", None) == 1:
                answers.add(str(rr.rdata))
        if not answers:
            return
        qname = dns.qd.qname.decode(errors="ignore") if dns.qd else "?"
        key = (dns.id, qname, pkt[IP].dst)
        now = time.time()
        for k in [k for k, v in self.dns_seen.items() if now - v[1] > 10]:
            del self.dns_seen[k]
        prev = self.dns_seen.get(key)
        if prev is None:
            self.dns_seen[key] = (answers, now)
        elif prev[0] != answers:
            self.once(("dns", key, tuple(sorted(answers))), "CRITICAL",
                      "Conflicting DNS replies (DNS spoofing)",
                      f"{qname}: {sorted(prev[0])} vs {sorted(answers)} "
                      f"from {pkt[IP].src}")

    def run(self):
        try:
            from scapy.all import sniff
        except ImportError:
            sys.exit("scapy is required for monitor mode:  pip install scapy")
        if not is_admin():
            sys.exit("Monitor mode needs administrator/root privileges.")
        info(f"Monitoring on {self.iface or 'default interface'} | gateway {self.gw_ip} "
             f"| prevention {'ON' if self.prevent else 'OFF'}")
        info("Press Ctrl+C to stop.")
        sniff(filter="arp or udp port 53", prn=self.handle, store=0, iface=self.iface)


def cmd_monitor(args):
    Monitor(args.prevent, args.gateway_mac, args.iface).run()


# --------------------------------------------------------------------------
# Mode: tls
# --------------------------------------------------------------------------
def cmd_tls(args):
    host, port = args.host, args.port
    pins = {}
    if os.path.exists(PIN_FILE):
        with open(PIN_FILE) as f:
            pins = json.load(f)

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                issuer = dict(x[0] for x in tls.getpeercert()["issuer"])
        chain_ok = True
    except ssl.SSLCertVerificationError as exc:
        alert("CRITICAL", "Certificate validation FAILED",
              f"{host}:{port} -> {exc.verify_message} (possible TLS interception)")
        chain_ok = False
        ctx2 = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx2.wrap_socket(s, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        issuer = {}
    except Exception as exc:
        sys.exit(f"Connection error: {exc}")

    fp = hashlib.sha256(der).hexdigest()
    key = f"{host}:{port}"
    print(f"    SHA-256 fingerprint: {fp}")
    if issuer:
        print(f"    Issuer: {issuer.get('organizationName', issuer)}")

    if key not in pins:
        if chain_ok or args.force_pin:
            pins[key] = fp
            with open(PIN_FILE, "w") as f:
                json.dump(pins, f, indent=2)
            info(f"First contact: fingerprint pinned for {key}")
        else:
            alert("WARNING", "Not pinned", "Chain invalid, refusing to pin (use --force-pin).")
    elif pins[key] != fp:
        alert("CRITICAL", "Pinned certificate CHANGED",
              f"{key}: expected {pins[key][:16]}... got {fp[:16]}... "
              "(could be a MITM proxy or a legitimate renewal - verify out of band)")
    else:
        info("Certificate matches the pinned fingerprint.")


# --------------------------------------------------------------------------
# Mode: harden
# --------------------------------------------------------------------------
def cmd_harden(args):
    gw_ip, iface = get_gateway()
    mac = norm_mac(args.gateway_mac) if args.gateway_mac else get_arp_table().get(gw_ip)
    if not gw_ip or not mac:
        sys.exit("Could not determine gateway IP/MAC. Pass --gateway-mac.")
    info(f"Pinning {gw_ip} -> {mac} (verify this MAC is the real router first!)")
    pin_gateway(gw_ip, mac, args.iface or iface)


# --------------------------------------------------------------------------
def main():
    show_banner()
    p = argparse.ArgumentParser(description="MITM Detection & Prevention Tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="audit the ARP table once").set_defaults(fn=cmd_scan)

    m = sub.add_parser("monitor", help="live ARP/DNS attack monitoring")
    m.add_argument("--iface")
    m.add_argument("--gateway-mac", help="known-good gateway MAC (recommended)")
    m.add_argument("--prevent", action="store_true",
                   help="auto-pin gateway ARP entry and block attacker MAC")
    m.set_defaults(fn=cmd_monitor)

    t = sub.add_parser("tls", help="check/pin a server's TLS certificate")
    t.add_argument("host")
    t.add_argument("--port", type=int, default=443)
    t.add_argument("--force-pin", action="store_true")
    t.set_defaults(fn=cmd_tls)

    h = sub.add_parser("harden", help="static ARP entry for the gateway")
    h.add_argument("--iface")
    h.add_argument("--gateway-mac")
    h.set_defaults(fn=cmd_harden)

    args = p.parse_args()
    try:
        args.fn(args)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")


if __name__ == "__main__":
    main()
