#!/usr/bin/env python3
"""
Metadata Extractor (Forensics)
Coded by Mr Sabaz Ali Khan - Cyber Security Engineer

Extracts forensic metadata from files:
  * Hashes (MD5 / SHA-1 / SHA-256), size, filesystem timestamps, permissions
  * Magic-byte file type detection + extension mismatch warning
  * Image EXIF (camera, software, timestamps, GPS -> decimal + map link)
  * PDF document info (author, creator, producer, dates, encryption)
  * Office OOXML (docx/xlsx/pptx) core + app properties, macro detection
  * Printable-string IOC hints (URLs, emails, IPv4) for any file

Optional deps (tool still works without them):
    pip install pillow pypdf

Usage:
    python metadata_extractor.py evidence.jpg
    python metadata_extractor.py ./case_folder -r -o report.json
    python metadata_extractor.py ./case_folder -r -o report.csv
"""

import argparse
import csv
import hashlib
import json
import mimetypes
import os
import re
import stat
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⠶⠶⠶⠶⠶⠶⠶⢖⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠞⠛⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⡞⠁⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠈⠹⣦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣼⠋⠀⠀⠀⢀⣤⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⣦⣀⠀⠀⠀⠈⢿⣄⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡾⠁⠀⣠⡾⢁⣾⡿⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣆⠹⣦⠀⠀⢻⣆⠀⠀⠀⠀
⠀⠀⢀⡾⠁⢀⢰⣿⠃⠾⢋⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⠀⢹⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡌⠻⠆⢿⣧⢀⠀⢻⣆⠀⠀⠀
⠀⠀⣾⠁⢠⡆⢸⡟⣠⣶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣦⡸⣿⠀⣆⠀⢿⡄⠀⠀
⠀⢸⡇⠀⣽⡇⢸⣿⠟⢡⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣉⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⠙⢿⣿⠀⣿⡀⠘⣿⠀⠀
⡀⣿⠁⠀⣿⡇⠘⣡⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⣦⡙⠀⣿⡇⠀⢻⡇⠀
⢸⡟⠀⡄⢻⣧⣾⡿⢋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣴⣿⠉⡄⢸⣿⠀
⢾⡇⢰⣧⠸⣿⡏⢠⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠀⠓⢶⠶⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣆⠙⣿⡟⢰⡧⠀⣿⠀
⣸⡇⠰⣿⡆⠹⣠⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⣿⡏⠀⠠⢺⠢⠀⠀⣿⣷⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⠸⠁⣾⡇⠀⣿⠀
⣿⡇⠀⢻⣷⠀⣿⡿⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡅⠀⠀⢸⡄⠀⠀⣿⣿⣿⣿⣿⣿⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡆⣰⣿⠁⠀⣿⠀
⢸⣧⠀⡈⢿⣷⣿⠃⣰⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣇⠀⢀⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣸⡀⢿⣧⣿⠃⡀⢸⣿⠀
⠀⣿⡀⢷⣄⠹⣿⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⣿⣿⠀⣼⣿⣿⣿⣿⣿⣿⣿⡯⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⢸⡟⢁⣴⠇⣼⡇⠀
⠀⢸⡇⠘⣿⣷⡈⢰⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⣿⣿⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢰⣿⡧⠈⣴⣿⠏⢠⣿⠀⠀
⠀⠀⢿⡄⠘⢿⣿⣦⣿⣯⠘⣆⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⡎⢸⣿⣣⣾⡿⠏⠀⣾⠇⠀⠀
⠀⠀⠈⢷⡀⢦⣌⠛⠿⣿⡀⢿⣆⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢀⣿⡁⣼⡿⠟⣉⣴⠂⣼⠏⠀⠀⠀
⠀⠀⠀⠈⢷⡈⠻⣿⣶⣤⡁⠸⣿⣆⠡⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢀⣾⡟⠀⣡⣴⣾⡿⠁⣴⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢿⣄⠈⢙⠿⢿⣷⣼⣿⣦⠹⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⢡⣾⣿⣶⣿⠿⢛⠉⢀⣾⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠹⣧⡀⠳⣦⣌⣉⣙⠛⠃⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠐⠛⠋⣉⣉⣤⡶⠁⣰⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⡀⠙⠛⠿⠿⠿⠿⠟⠛⠛⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠙⠟⠛⠿⠿⠿⠿⠟⠛⠁⣠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢶⣄⠙⠶⣦⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⣤⡶⠖⣁⣴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣶⣄⡉⠉⠉⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠉⠉⠉⠉⣡⣴⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠷⢦⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣠⣴⠶⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "METADATA EXTRACTOR (FORENSICS)"
CREDIT = "Coded by Mr Sabaz Ali Khan | Cyber Security Engineer"

# --------------------------------------------------------------------------
# Magic-byte signatures: (offset, bytes) -> (type name, expected extensions)
# --------------------------------------------------------------------------
SIGNATURES = [
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"BM", "BMP image", {".bmp"}),
    (b"II*\x00", "TIFF image", {".tif", ".tiff"}),
    (b"MM\x00*", "TIFF image", {".tif", ".tiff"}),
    (b"%PDF-", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP container (zip/docx/xlsx/pptx/jar/apk)",
     {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy doc/xls/ppt/msi)",
     {".doc", ".xls", ".ppt", ".msi"}),
    (b"MZ", "Windows PE executable", {".exe", ".dll", ".sys", ".scr"}),
    (b"\x7fELF", "ELF executable", {"", ".so", ".elf", ".bin"}),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"\x1f\x8b", "GZIP archive", {".gz", ".tgz"}),
    (b"ID3", "MP3 audio (ID3)", {".mp3"}),
    (b"SQLite format 3\x00", "SQLite database", {".db", ".sqlite", ".sqlite3"}),
    (b"{\\rtf", "RTF document", {".rtf"}),
]

OOXML_EXT = {".docx", ".xlsx", ".pptx"}

URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,200}")
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,255}\.[A-Za-z]{2,10}")
IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def hash_file(path, chunk=1024 * 1024):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def detect_type(path):
    with open(path, "rb") as fh:
        head = fh.read(32)
    for magic, name, exts in SIGNATURES:
        if head.startswith(magic):
            return name, exts
    return None, set()


def clean(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value.replace("\x00", "").strip()
    return value


# --------------------------------------------------------------------------
# Extractors
# --------------------------------------------------------------------------
def fs_metadata(path):
    st = os.stat(path)
    info = {
        "size": st.st_size,
        "size_human": human_size(st.st_size),
        "modified": ts(st.st_mtime),
        "accessed": ts(st.st_atime),
        # On Windows st_ctime = creation time; on Linux/macOS it is inode-change time.
        "created_or_inode_changed": ts(st.st_ctime),
        "permissions": stat.filemode(st.st_mode),
        "owner_uid": getattr(st, "st_uid", None),
        "group_gid": getattr(st, "st_gid", None),
        "is_symlink": os.path.islink(path),
    }
    return info


def dms_to_deg(dms, ref):
    try:
        d, m, s = (float(x) for x in dms)
        deg = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            deg = -deg
        return round(deg, 7)
    except Exception:
        return None


def extract_image(path):
    if not HAS_PIL:
        return {"note": "Install Pillow for EXIF: pip install pillow"}
    out = {}
    try:
        with Image.open(path) as img:
            out["format"] = img.format
            out["dimensions"] = f"{img.width}x{img.height}"
            out["mode"] = img.mode
            exif = img.getexif()
            if not exif:
                out["exif"] = "No EXIF data found (possibly stripped)"
                return out

            tags = {}
            for tag_id, val in exif.items():
                tags[ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")] = val

            # Sub-IFD (Exif) holds DateTimeOriginal, lens, exposure, etc.
            try:
                for tag_id, val in exif.get_ifd(0x8769).items():
                    tags[ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")] = val
            except Exception:
                pass

            skip = {"MakerNote", "UserComment", "PrintImageMatching", "ExifOffset", "GPSInfo"}
            out["exif"] = {k: clean(v) if not isinstance(v, (bytes, bytearray)) or len(v) < 128
                           else f"<{len(v)} bytes>"
                           for k, v in tags.items() if k not in skip}

            # GPS
            try:
                gps_raw = exif.get_ifd(0x8825)
            except Exception:
                gps_raw = {}
            if gps_raw:
                gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
                lat = dms_to_deg(gps.get("GPSLatitude", ()), gps.get("GPSLatitudeRef"))
                lon = dms_to_deg(gps.get("GPSLongitude", ()), gps.get("GPSLongitudeRef"))
                geo = {"raw": {k: str(v) for k, v in gps.items()}}
                if lat is not None and lon is not None:
                    geo["latitude"] = lat
                    geo["longitude"] = lon
                    geo["map_link"] = f"https://www.google.com/maps?q={lat},{lon}"
                out["gps"] = geo
    except Exception as exc:
        out["error"] = f"Image parse failed: {exc}"
    return out


def extract_pdf(path):
    if not HAS_PYPDF:
        return {"note": "Install pypdf for PDF metadata: pip install pypdf"}
    out = {}
    try:
        reader = PdfReader(path)
        out["encrypted"] = reader.is_encrypted
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                out["note"] = "Encrypted - metadata may be unreadable without password"
        out["pages"] = len(reader.pages)
        meta = reader.metadata or {}
        out["info"] = {str(k).lstrip("/"): clean(str(v)) for k, v in meta.items()}
        root = reader.trailer["/Root"]
        out["has_javascript"] = "/JavaScript" in str(root) or "/JS" in str(root)
        out["has_embedded_files"] = "/EmbeddedFiles" in str(root)
        out["has_auto_action"] = "/OpenAction" in root
    except Exception as exc:
        out["error"] = f"PDF parse failed: {exc}"
    return out


def _strip_ns(tag):
    return tag.split("}", 1)[-1]


def extract_ooxml(path):
    out = {}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            for part, label in (("docProps/core.xml", "core"), ("docProps/app.xml", "app")):
                if part in names:
                    root = ET.fromstring(zf.read(part))
                    out[label] = {_strip_ns(c.tag): clean(c.text or "") for c in root if (c.text or "").strip()}
            out["has_macros"] = any("vbaProject.bin" in n for n in names)
            out["embedded_objects"] = [n for n in names if "/embeddings/" in n][:20]
            out["external_links"] = []
            for n in names:
                if n.endswith(".rels"):
                    data = zf.read(n).decode("utf-8", "replace")
                    out["external_links"] += re.findall(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"', data)
            out["external_links"] = sorted(set(out["external_links"]))[:20]
            out["part_count"] = len(names)
    except zipfile.BadZipFile:
        out["error"] = "Corrupt or non-ZIP container"
    except Exception as exc:
        out["error"] = f"OOXML parse failed: {exc}"
    return out


def extract_iocs(path, limit_bytes=20 * 1024 * 1024):
    """Pull URLs / emails / IPv4 addresses out of the raw bytes (first 20 MB)."""
    with open(path, "rb") as fh:
        data = fh.read(limit_bytes)
    found = {
        "urls": sorted({m.decode("ascii", "ignore") for m in URL_RE.findall(data)})[:25],
        "emails": sorted({m.decode("ascii", "ignore") for m in EMAIL_RE.findall(data)})[:25],
        "ipv4": sorted({m.decode("ascii", "ignore") for m in IPV4_RE.findall(data)})[:25],
    }
    return {k: v for k, v in found.items() if v}


# --------------------------------------------------------------------------
# Main analysis
# --------------------------------------------------------------------------
def analyze(path, with_iocs=True):
    report = {"path": os.path.abspath(path), "name": os.path.basename(path)}
    ext = os.path.splitext(path)[1].lower()
    flags = []

    try:
        report["filesystem"] = fs_metadata(path)
        report["hashes"] = hash_file(path)
        type_name, expected = detect_type(path)
        report["detected_type"] = type_name or "Unknown / text / no known signature"
        report["mime_guess"] = mimetypes.guess_type(path)[0] or "unknown"

        if type_name and ext not in expected:
            flags.append(f"EXTENSION MISMATCH: extension '{ext or 'none'}' but content is {type_name}")

        if type_name and type_name.startswith("JPEG") or type_name in (
                "PNG image", "GIF image", "BMP image", "TIFF image"):
            report["image"] = extract_image(path)
            if "gps" in report["image"]:
                flags.append("GPS location embedded in image")
        elif type_name == "PDF document":
            report["pdf"] = extract_pdf(path)
            if report["pdf"].get("has_javascript"):
                flags.append("PDF contains JavaScript")
            if report["pdf"].get("has_auto_action"):
                flags.append("PDF has OpenAction (auto-executes on open)")
        elif zipfile.is_zipfile(path) and (ext in OOXML_EXT or type_name and "ZIP" in type_name):
            ooxml = extract_ooxml(path)
            if "core" in ooxml or "app" in ooxml:
                report["office"] = ooxml
                if ooxml.get("has_macros"):
                    flags.append("Office document contains VBA macros")
                if ooxml.get("external_links"):
                    flags.append("Office document references external URLs")

        if type_name == "Windows PE executable":
            flags.append("Windows executable - handle in an isolated environment")

        if with_iocs:
            iocs = extract_iocs(path)
            if iocs:
                report["indicators"] = iocs
    except PermissionError:
        report["error"] = "Permission denied"
    except Exception as exc:
        report["error"] = str(exc)

    report["flags"] = flags
    return report


def collect_files(targets, recursive):
    files = []
    for t in targets:
        if os.path.isfile(t):
            files.append(t)
        elif os.path.isdir(t):
            if recursive:
                for root, _, names in os.walk(t):
                    files += [os.path.join(root, n) for n in sorted(names)]
            else:
                files += [os.path.join(t, n) for n in sorted(os.listdir(t))
                          if os.path.isfile(os.path.join(t, n))]
        else:
            print(f"[!] Not found: {t}", file=sys.stderr)
    return files


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def print_section(title, data, indent=2):
    pad = " " * indent
    print(f"{pad}[{title}]")
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                print(f"{pad}  {k}:")
                for k2, v2 in v.items():
                    print(f"{pad}    {k2}: {v2}")
            elif isinstance(v, list):
                print(f"{pad}  {k}:")
                for item in v:
                    print(f"{pad}    - {item}")
            else:
                print(f"{pad}  {k}: {v}")
    else:
        print(f"{pad}  {data}")


def print_report(rep):
    print("=" * 78)
    print(f"FILE : {rep['path']}")
    print("=" * 78)
    if "error" in rep:
        print(f"  [!] ERROR: {rep['error']}")
    for key, title in (("filesystem", "FILESYSTEM"), ("hashes", "HASHES")):
        if key in rep:
            print_section(title, rep[key])
    if "detected_type" in rep:
        print_section("TYPE", {"detected": rep["detected_type"], "mime_guess": rep["mime_guess"]})
    for key, title in (("image", "IMAGE / EXIF"), ("pdf", "PDF"), ("office", "OFFICE"),
                       ("indicators", "INDICATORS (URLs / emails / IPs)")):
        if key in rep:
            print_section(title, rep[key])
    if rep.get("flags"):
        print("  [FORENSIC FLAGS]")
        for f in rep["flags"]:
            print(f"    (!) {f}")
    print()


def flatten(d, prefix=""):
    flat = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flat.update(flatten(v, key + "."))
        elif isinstance(v, list):
            flat[key] = "; ".join(map(str, v))
        else:
            flat[key] = v
    return flat


def save_report(reports, out_path):
    if out_path.lower().endswith(".csv"):
        rows = [flatten(r) for r in reports]
        cols = sorted({c for r in rows for c in r})
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
    else:
        payload = {
            "tool": TITLE,
            "coded_by": CREDIT,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "results": reports,
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str, ensure_ascii=False)
    print(f"[+] Report saved to {out_path}")


def show_banner():
    print(BANNER)
    print(TITLE.center(78))
    print(CREDIT.center(78))
    print("-" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="Metadata Extractor (Forensics) - coded by Mr Sabaz Ali Khan")
    parser.add_argument("targets", nargs="+", help="file(s) or folder(s) to analyze")
    parser.add_argument("-r", "--recursive", action="store_true", help="recurse into folders")
    parser.add_argument("-o", "--output", help="save report (.json or .csv)")
    parser.add_argument("--no-iocs", action="store_true", help="skip URL/email/IP string scan")
    parser.add_argument("--no-banner", action="store_true", help="hide the banner")
    args = parser.parse_args()

    if not args.no_banner:
        show_banner()

    files = collect_files(args.targets, args.recursive)
    if not files:
        print("[!] No files to analyze.")
        sys.exit(1)

    print(f"[*] Analyzing {len(files)} file(s)...\n")
    reports = []
    for f in files:
        rep = analyze(f, with_iocs=not args.no_iocs)
        reports.append(rep)
        print_report(rep)

    flagged = sum(1 for r in reports if r.get("flags"))
    print(f"[*] Done. {len(reports)} analyzed, {flagged} with forensic flags.")

    if args.output:
        save_report(reports, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
