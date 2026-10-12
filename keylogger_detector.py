#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Keylogger Detector / Malware Analyzer
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Defensive tool. Scans running processes, persistence locations and files
for keylogger / spyware indicators using heuristics (names, paths, API
imports, entropy, packers, network behaviour).

Usage:
    python keylogger_detector.py processes
    python keylogger_detector.py persistence
    python keylogger_detector.py file  <path>
    python keylogger_detector.py dir   <path> [--max-mb 50]
    python keylogger_detector.py full  [--dir <path>] [--json report.json]

Optional dependency (recommended):  pip install psutil
Only scan systems you own or are authorized to assess.
"""

import argparse
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠐⡈⠐⠠⢁⠂⠐⢀⣾⣿⡿⠿⠿⠿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠿⣷⡄⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠐⠠⢁⠂⠄⠀⣛⠀⡟⢁⣠⣄⠀⠀⠀⠙⢻⡟⠉⠀⠀⢀⣴⣦⣬⠃⣬⣅⠀⢂⠐⡀⢂⠐⠠⠀⠄⠠⠀⠄⠠⢀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡁⢂⠈⠀⠾⡛⢱⡿⢿⣿⣿⣿⣦⣄⣠⣼⣷⣤⣤⣶⠿⠿⢿⣟⠆⢉⡛⠆⠀⢂⠐⠠⠈⠄⠡⠈⠄⠡⢈⠐⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡐⢀⠂⢠⣾⡟⣸⣰⡿⠁⠀⠀⠙⣿⡇⣿⣿⠸⣿⠁⢀⣀⣀⣙⡸⠎⢿⡆⠀⠂⠌⠠⠁⠌⠠⠁⠌⡐⢀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⠀⠄⠀⠟⡸⢛⣤⣼⣿⣿⣿⣤⣼⠇⣿⣿⠀⢧⣿⣿⣿⣿⣿⣿⣧⣄⠃⠀⢃⠘⡀⢃⠘⡀⠃⠄⠠⢀⠘⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢂⠡⠈⠄⢈⡾⠋⢹⣿⣿⣿⣿⡟⢡⣴⣿⣿⣷⣦⡙⢿⣿⣿⣿⣿⠀⠙⠀⠈⡀⢂⠐⡀⠂⠄⠡⢈⠐⡀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠄⢂⠡⠀⢸⠀⠀⢸⣿⣿⣿⣿⡀⣿⣿⣿⣿⣿⣿⡇⠸⢿⣿⣿⡟⠀⠀⠀⠀⡐⢀⠂⠄⠡⢈⠐⡀⢂⠐⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠄⡐⠠⠀⠀⠀⠀⠙⠋⠉⠀⠀⠉⠉⠙⠛⠋⠉⠀⠀⠀⠀⠁⠀⠀⠀⠀⢀⠐⠠⠈⠄⡁⢂⠐⡀⠂⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢈⠐⠠⠁⠄⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢀⣀⠀⠀⢀⠂⠌⠠⢁⠂⡐⢀⠂⠄⠡⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⠈⠄⠡⢈⠐⡀⠸⣿⣦⡀⠀⠀⠛⠒⠚⠛⠛⠛⠛⠀⢀⣴⣿⠃⠀⠌⡀⠂⠌⡐⢀⠂⡐⠠⠈⠄⡁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠡⢈⠐⡀⠂⠄⠀⢻⣿⣿⣷⣶⣦⣤⣤⣤⣤⣤⣶⣾⣿⣿⡿⠀⠐⠠⢀⠁⢂⠐⡀⠂⠄⠡⢈⠐⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⡐⢀⠂⠄⠡⠈⠄⠘⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⡿⠃⠀⠌⡐⠠⠈⠄⠂⠄⠡⢈⠐⠠⠈⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡐⠠⠈⠄⠡⢈⠐⠀⠀⠙⠃⣿⣿⣿⣿⣿⣿⣿⣿⡗⠋⠀⣤⠀⠀⠀⠡⠈⠄⠡⢈⠐⠠⠈⠄⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠄⠡⠈⠄⡁⠂⠀⠀⣤⡀⠀⢻⣿⣿⣿⣿⣿⣿⣿⠇⣠⣾⣿⠀⣰⠀⠀⠀⣈⡀⠀⠈⠀⠁⠂⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡈⠄⠁⠂⠀⠀⠀⠀⢻⣿⣷⠬⠉⠉⠉⠉⠉⠉⠀⠚⢿⣿⣿⢀⣿⡀⠀⠀⢹⣿⣿⣿⣿⣶⡶⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⢸⣧⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⣾⣿⡇⠀⠁⠀⢻⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣟⡿⠀⠀⠀⠀⣿⣿⣦⠘⣿⣶⠖⣠⠆⠀⠀⢳⣤⡙⢿⣟⣼⣿⣿⡇⠀⠐⡀⠈⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⠃⠀⠀⠀⠀⢿⣿⣿⣷⣌⣿⣾⠏⠀⡀⠀⠸⡿⠿⠾⠿⠿⠿⠿⠷⠀⠀⠄⠀⠸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⢠⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⢠⠀⡄⣴⠀⠀⡄⠐⠀⠀⢻⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠠⠀⠀⠀⠀⢀⠀⠠⠀⠄⢂⠐⠠⢈⠐⡈⠐⡀⢂⠐⠘⢷⡭⠂⠄⡁⢂⠀⠈⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠡⠐⠠⠈⡐⠠⠈⠄⠡⠈⠄⡈⠐⡀⠂⠄⠡⠐⠠⠨⠄⠆⠠⠌⠠⠐⠠⢀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⡿⠿⠿⠀⣼⡿⠿⣿⡆⢠⣿⠿⢿⣷⠀⣼⡿⠿⣿⡆⢸⣿⠀⣿⡿⠿⠿⠀⠾⢿⣿⠿⠇⠘⣿⡄⣰⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣧⣤⡄⠀⢿⣧⣤⣤⡁⢨⣿⠀⢀⣿⠀⣿⡇⠀⠀⠁⢸⣿⠀⣿⣧⣤⡄⠀⠀⢸⣿⠀⠀⠀⠘⢿⣿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⡏⠁⠁⠀⣤⣍⣈⣿⡇⢸⣿⣀⣀⣿⠀⣿⣇⣀⣤⡄⢸⣿⠀⣿⣇⣉⣀⠀⠀⢸⣿⠀⠀⠀⠀⢸⣯⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠛⠃⠀⠀⠀⠙⠛⠛⠛⠁⠀⠛⠛⠛⠋⠀⠘⠛⠛⠛⠁⠘⠛⠀⠛⠛⠛⠛⠀⠀⠘⠛⠀⠀⠀⠀⠘⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = "Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer"
TITLE = "KEYLOGGER DETECTOR  /  MALWARE ANALYZER"

# ---------------------------------------------------------------- colours
if sys.stdout.isatty() and not (IS_WIN and "ANSICON" not in os.environ and "WT_SESSION" not in os.environ):
    C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "b": "\033[1m", "x": "\033[0m"}
else:
    C = {k: "" for k in ("r", "g", "y", "c", "b", "x")}


def show_banner():
    print(C["c"] + BANNER + C["x"])
    print(C["b"] + C["g"] + f"   {TITLE}" + C["x"])
    print(C["y"] + f"   {CREDIT}" + C["x"])
    print(C["c"] + "   " + "=" * 62 + C["x"] + "\n")


# ------------------------------------------------------------ indicators
# (byte pattern -> (weight, description))
BINARY_INDICATORS = {
    b"SetWindowsHookEx":        (4, "Installs global keyboard/mouse hook"),
    b"GetAsyncKeyState":        (4, "Polls key state (classic keylogger API)"),
    b"GetKeyboardState":        (3, "Reads keyboard state"),
    b"GetKeyState":             (2, "Reads key state"),
    b"GetRawInputData":         (3, "Raw input capture"),
    b"RegisterRawInputDevices": (3, "Registers raw input devices"),
    b"MapVirtualKey":           (2, "Maps virtual keys to characters"),
    b"AttachThreadInput":       (2, "Attaches to another thread's input"),
    b"GetForegroundWindow":     (2, "Tracks active window title"),
    b"GetClipboardData":        (2, "Reads clipboard"),
    b"keybd_event":             (1, "Synthesizes key events"),
    b"CreateRemoteThread":      (3, "Remote thread injection"),
    b"VirtualAllocEx":          (3, "Allocates memory in another process"),
    b"WriteProcessMemory":      (3, "Writes into another process"),
    b"IsDebuggerPresent":       (2, "Anti-debugging check"),
    b"URLDownloadToFile":       (3, "Downloads files from the internet"),
    b"InternetOpen":            (1, "Network exfiltration capability"),
    b"/dev/input/event":        (3, "Reads Linux input devices"),
    b"XGrabKeyboard":           (3, "X11 keyboard grab"),
    b"XQueryKeymap":            (3, "X11 key polling"),
    b"pynput":                  (4, "Python pynput keyboard library"),
    b"pyHook":                  (4, "Python pyHook keyboard hook"),
    b"pyxhook":                 (4, "Python pyxhook keyboard hook"),
    b"evdev":                   (2, "Linux evdev input access"),
    b"UPX0":                    (2, "UPX-packed binary"),
    b"UPX!":                    (2, "UPX-packed binary"),
}

SCRIPT_PATTERNS = [
    (r"from\s+pynput|import\s+pynput",              4, "Uses pynput keyboard listener"),
    (r"import\s+keyboard|keyboard\.(on_press|hook|record)", 4, "Uses 'keyboard' module hooks"),
    (r"pyHook|pyxhook",                             4, "Uses key hook library"),
    (r"GetAsyncKeyState|SetWindowsHookEx",          4, "Calls Win32 keylogging APIs"),
    (r"/dev/input/event",                           3, "Reads raw Linux input"),
    (r"smtplib|ftplib|requests\.post|urllib",       1, "Network/exfil capability"),
    (r"ImageGrab|pyautogui\.screenshot|mss\(",      2, "Takes screenshots"),
    (r"pyperclip|GetClipboardData",                 2, "Reads clipboard"),
    (r"winreg|CurrentVersion\\\\Run",               2, "Registry persistence"),
    (r"base64\.b64decode|exec\(|eval\(",            2, "Obfuscated/dynamic execution"),
    (r"win32gui\.GetForegroundWindow|GetWindowText",2, "Tracks active window"),
]

SUSPICIOUS_NAMES = [
    "keylog", "logkeys", "ardamax", "revealer", "kidlogger", "refog", "spyrix",
    "actualspy", "hookspy", "pykeylogger", "klog", "keyspy", "keycapture",
    "keystroke", "spybot", "snoop", "hawkeye", "agenttesla", "formbook", "lokibot",
]

SUSPICIOUS_PATH_PARTS = [
    "\\temp\\", "/tmp/", "\\appdata\\local\\temp", "\\appdata\\roaming\\", "\\downloads\\",
    "/dev/shm", "\\programdata\\", "/var/tmp/", "\\users\\public\\",
]

SCRIPT_EXT = {".py", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".sh", ".pyw"}
BIN_EXT = {".exe", ".dll", ".scr", ".sys", ".so", ".bin", ".elf", ".jar", ".msi"}


# ---------------------------------------------------------------- helpers
def verdict(score):
    if score >= 9:
        return "LIKELY MALICIOUS", C["r"]
    if score >= 4:
        return "SUSPICIOUS", C["y"]
    return "CLEAN / LOW RISK", C["g"]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def hashes(path, limit=200 * 1024 * 1024):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            read += len(chunk)
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
            if read > limit:
                break
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def file_type(head: bytes, ext: str):
    if head[:2] == b"MZ":
        return "PE executable (Windows)"
    if head[:4] == b"\x7fELF":
        return "ELF executable (Linux)"
    if head[:4] == b"PK\x03\x04":
        return "ZIP/JAR/Office archive"
    if head[:2] == b"#!" or ext in SCRIPT_EXT:
        return "Script"
    return "Unknown/data"


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


def load_blacklist(path):
    """Optional text file: one SHA256 per line."""
    if not path or not os.path.isfile(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}


# --------------------------------------------------------------- file scan
def analyze_file(path, max_mb=50, blacklist=frozenset()):
    result = {"path": str(path), "score": 0, "reasons": [], "indicators": []}
    try:
        size = os.path.getsize(path)
        result["size"] = size
        ext = Path(path).suffix.lower()
        with open(path, "rb") as f:
            data = f.read(max_mb * 1024 * 1024)
        result["type"] = file_type(data[:8], ext)
        result["hashes"] = hashes(path)
        result["entropy"] = round(entropy(data), 3)

        if result["hashes"]["sha256"] in blacklist:
            result["score"] += 20
            result["reasons"].append("SHA256 matches known-bad hash list")

        name = Path(path).name.lower()
        for n in SUSPICIOUS_NAMES:
            if n in name:
                result["score"] += 4
                result["reasons"].append(f"Suspicious file name keyword '{n}'")
                break

        is_script = result["type"] == "Script"
        if is_script:
            text = data.decode("utf-8", errors="ignore")
            for pat, w, desc in SCRIPT_PATTERNS:
                if re.search(pat, text, re.I):
                    result["score"] += w
                    result["indicators"].append(desc)
        else:
            for sig, (w, desc) in BINARY_INDICATORS.items():
                if sig in data:
                    result["score"] += w
                    result["indicators"].append(f"{sig.decode(errors='ignore')}: {desc}")

        if result["entropy"] > 7.2 and not is_script and size > 20 * 1024:
            result["score"] += 2
            result["reasons"].append(f"High entropy ({result['entropy']}) - packed/encrypted")

        low = str(path).lower()
        if any(p in low for p in SUSPICIOUS_PATH_PARTS) and result["type"] != "Unknown/data":
            result["score"] += 1
            result["reasons"].append("Located in a commonly abused directory")

        # Keylogger-specific combo: capture API + exfil/persistence
        joined = " ".join(result["indicators"]).lower()
        capture = any(k in joined for k in ("keyboard", "keystroke", "hook", "pynput", "getasynckeystate", "/dev/input"))
        exfil = any(k in joined for k in ("network", "exfil", "internet", "smtp", "download"))
        if capture and exfil:
            result["score"] += 3
            result["reasons"].append("Combination: key capture + network exfiltration capability")

        # Optional PE details
        if result["type"].startswith("PE"):
            try:
                import pefile  # type: ignore
                pe = pefile.PE(data=data, fast_load=False)
                result["pe_timestamp"] = time.strftime("%Y-%m-%d", time.gmtime(pe.FILE_HEADER.TimeDateStamp))
                result["pe_sections"] = [s.Name.rstrip(b"\x00").decode(errors="ignore") for s in pe.sections]
                if any(s.get_entropy() > 7.4 for s in pe.sections):
                    result["score"] += 1
                    result["reasons"].append("PE section with very high entropy")
            except Exception:
                pass
    except (PermissionError, FileNotFoundError, OSError) as e:
        result["error"] = str(e)

    result["verdict"] = verdict(result["score"])[0]
    return result


def scan_dir(root, max_mb=50, blacklist=frozenset()):
    found = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            ext = Path(fn).suffix.lower()
            if ext in SCRIPT_EXT or ext in BIN_EXT:
                try:
                    if os.path.getsize(p) > max_mb * 1024 * 1024:
                        continue
                except OSError:
                    continue
                r = analyze_file(p, max_mb, blacklist)
                if r["score"] >= 4:
                    found.append(r)
    return sorted(found, key=lambda x: -x["score"])


# ------------------------------------------------------------ process scan
def linux_input_fds(pid):
    hits = []
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
                if target.startswith("/dev/input/event"):
                    hits.append(target)
            except OSError:
                continue
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        pass
    return hits


def scan_processes(blacklist=frozenset()):
    if psutil is None:
        print(C["r"] + "[!] psutil not installed: pip install psutil" + C["x"])
        return []
    results = []
    me = os.getpid()
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        info = p.info
        if info["pid"] == me:
            continue
        score, reasons = 0, []
        name = (info["name"] or "").lower()
        exe = info["exe"] or ""
        cmd = " ".join(info["cmdline"] or [])

        for n in SUSPICIOUS_NAMES:
            if n in name or n in cmd.lower():
                score += 5
                reasons.append(f"Known/suspicious keyword '{n}'")
                break

        if exe and any(s in exe.lower() for s in SUSPICIOUS_PATH_PARTS):
            score += 2
            reasons.append(f"Runs from abused location: {exe}")

        if IS_LINUX:
            if exe.endswith("(deleted)"):
                score += 3
                reasons.append("Binary deleted from disk while running")
            ev = linux_input_fds(info["pid"])
            if ev:
                score += 4
                reasons.append(f"Holds input device open: {', '.join(ev[:3])}")

        if any(k in cmd.lower() for k in ("pynput", "pyhook", "keyboard", "pyxhook")):
            score += 3
            reasons.append("Command line references keyboard hook library")

        # script / binary static analysis
        target = None
        if exe and os.path.isfile(exe) and not exe.startswith(("C:\\Windows", "/usr/", "/bin", "/sbin", "/lib")):
            target = exe
        for arg in (info["cmdline"] or [])[1:]:
            if arg.lower().endswith(tuple(SCRIPT_EXT)) and os.path.isfile(arg):
                target = arg
                break
        if target:
            fr = analyze_file(target, 20, blacklist)
            if fr["score"] >= 4:
                score += min(fr["score"], 8)
                reasons.append(f"Static analysis of {target}: {fr['verdict']} ({fr['score']})")
                reasons.extend(fr["indicators"][:4])

        # network
        try:
            getter = getattr(p, "net_connections", None) or p.connections
            ext = [c for c in getter(kind="inet") if c.raddr and c.status == "ESTABLISHED" and not is_private(c.raddr.ip)]
            if ext and score > 0:
                score += 2
                reasons.append(f"Active external connection(s): {', '.join(f'{c.raddr.ip}:{c.raddr.port}' for c in ext[:3])}")
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        if score >= 4:
            results.append({"pid": info["pid"], "name": info["name"], "exe": exe,
                            "user": info["username"], "score": score,
                            "verdict": verdict(score)[0], "reasons": reasons})
    return sorted(results, key=lambda x: -x["score"])


# ---------------------------------------------------------- persistence
def scan_persistence():
    entries = []

    def add(location, name, command):
        score, why = 0, []
        low = (command or "").lower()
        if any(s in low for s in SUSPICIOUS_PATH_PARTS):
            score += 2; why.append("Points to abused directory")
        if any(n in low or n in (name or "").lower() for n in SUSPICIOUS_NAMES):
            score += 5; why.append("Suspicious keyword")
        if re.search(r"powershell.*-(enc|e|w\s+hidden)|wscript|cscript|mshta|curl .*\|\s*(ba)?sh|base64 -d", low):
            score += 3; why.append("Script/LOLBin launcher or encoded command")
        entries.append({"location": location, "name": name, "command": command,
                        "score": score, "reasons": why, "verdict": verdict(score)[0]})

    if IS_WIN:
        try:
            import winreg
            keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")]
            for hive, sub in keys:
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        i = 0
                        while True:
                            try:
                                n, v, _ = winreg.EnumValue(k, i)
                                add(f"Registry:{sub}", n, str(v))
                                i += 1
                            except OSError:
                                break
                except OSError:
                    continue
        except ImportError:
            pass
        startup = [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")]
    else:
        home = str(Path.home())
        startup = [f"{home}/.config/autostart", f"{home}/.config/systemd/user",
                   "/etc/xdg/autostart", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily"]
        for cf in ("/etc/crontab", f"/var/spool/cron/crontabs/{os.environ.get('USER', '')}"):
            try:
                with open(cf, "r", errors="ignore") as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            add(f"Cron:{cf}", "cron entry", line.strip())
            except OSError:
                pass

    for d in startup:
        if os.path.isdir(d):
            for fn in os.listdir(d):
                full = os.path.join(d, fn)
                try:
                    with open(full, "r", errors="ignore") as f:
                        content = f.read(2000)
                except OSError:
                    content = ""
                add(f"Startup:{d}", fn, full + " " + content.replace("\n", " "))
    return sorted(entries, key=lambda x: -x["score"])


# --------------------------------------------------------------- reporting
def print_section(title):
    print(C["b"] + C["c"] + f"\n[+] {title}" + C["x"])
    print(C["c"] + "-" * 66 + C["x"])


def print_findings(items, kind):
    flagged = [i for i in items if i.get("score", 0) >= 4]
    if not flagged:
        print(C["g"] + "   No suspicious findings." + C["x"])
        return
    for i in flagged:
        label, col = verdict(i["score"])
        if kind == "process":
            print(f"{col}   [{label}] PID {i['pid']}  {i['name']}  (score {i['score']}){C['x']}")
            print(f"      exe: {i['exe']}  user: {i['user']}")
        elif kind == "persistence":
            print(f"{col}   [{label}] {i['name']}  (score {i['score']}){C['x']}")
            print(f"      where: {i['location']}")
            print(f"      cmd  : {i['command'][:140]}")
        else:
            print(f"{col}   [{label}] {i['path']}  (score {i['score']}){C['x']}")
        for r in i.get("reasons", []):
            print(f"      - {r}")
        for r in i.get("indicators", [])[:8]:
            print(f"      * {r}")


def print_file_report(r):
    print_section(f"File Analysis: {r['path']}")
    if "error" in r:
        print(C["r"] + f"   Error: {r['error']}" + C["x"])
        return
    label, col = verdict(r["score"])
    print(f"   Type    : {r['type']}")
    print(f"   Size    : {r['size']:,} bytes")
    print(f"   Entropy : {r['entropy']}")
    for k, v in r["hashes"].items():
        print(f"   {k.upper():7s} : {v}")
    if "pe_timestamp" in r:
        print(f"   PE time : {r['pe_timestamp']}   sections: {', '.join(r['pe_sections'])}")
    print(f"\n   Verdict : {col}{label}{C['x']}  (score {r['score']})")
    for x in r["reasons"]:
        print(f"      - {x}")
    for x in r["indicators"]:
        print(f"      * {x}")


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=TITLE + " - " + CREDIT)
    sub = ap.add_subparsers(dest="mode")
    sub.add_parser("processes", help="scan running processes")
    sub.add_parser("persistence", help="scan startup/persistence locations")
    f = sub.add_parser("file", help="analyze a single file"); f.add_argument("path")
    d = sub.add_parser("dir", help="scan a directory"); d.add_argument("path"); d.add_argument("--max-mb", type=int, default=50)
    fu = sub.add_parser("full", help="processes + persistence (+ optional dir)")
    fu.add_argument("--dir"); fu.add_argument("--json", help="save JSON report")
    ap.add_argument("--blacklist", help="file of known-bad SHA256 hashes (one per line)")
    args = ap.parse_args()

    show_banner()
    if not args.mode:
        ap.print_help()
        return

    bl = load_blacklist(args.blacklist)
    report = {"tool": TITLE, "author": "Mr Sabaz Ali Khan", "time": time.strftime("%Y-%m-%d %H:%M:%S"),
              "host": platform.node(), "os": platform.platform()}

    if args.mode in ("processes", "full"):
        print_section("Running Process Scan")
        res = scan_processes(bl); print_findings(res, "process"); report["processes"] = res
    if args.mode in ("persistence", "full"):
        print_section("Persistence / Startup Scan")
        res = scan_persistence(); print_findings(res, "persistence"); report["persistence"] = res
    if args.mode == "file":
        r = analyze_file(args.path, 200, bl); print_file_report(r); report["file"] = r
    if args.mode == "dir" or (args.mode == "full" and args.dir):
        root = args.path if args.mode == "dir" else args.dir
        print_section(f"Directory Scan: {root}")
        res = scan_dir(root, getattr(args, "max_mb", 50), bl); print_findings(res, "file"); report["files"] = res

    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(C["g"] + f"\n[✓] Report saved to {args.json}" + C["x"])

    print(C["y"] + f"\n{CREDIT}" + C["x"])
    print("Note: results are heuristic. Verify flagged items before removal (false positives are possible).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
