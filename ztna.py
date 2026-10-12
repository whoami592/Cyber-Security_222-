#!/usr/bin/env python3
"""
Zero Trust Network Access (ZTNA) System
Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan

Principles implemented ("never trust, always verify"):
  * Strong identity   : PBKDF2 password hashing + TOTP MFA (RFC 6238)
  * Device trust      : posture checks (patching, encryption, firewall, EDR)
  * Least privilege   : deny-by-default, per-resource policies
  * Continuous verify : every request re-evaluated (token + device + risk)
  * Short-lived tokens: HMAC-signed, device-bound, revocable
  * Brute-force guard : per-user lockout
  * Tamper-evident log: hash-chained audit trail

Usage:
  python ztna.py demo      # run scripted scenarios
  python ztna.py serve     # start the HTTP gateway on 127.0.0.1:8443
Standard library only. Python 3.9+.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣶⣦⡄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣀⣀⡀⢀⠀⢹⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣷⣄⠨⣿⣿⣿⡌⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣷⣿⣿⣿⣿⣿⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣴⣾⣿⣮⣝⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠉⠙⠻⢿⣿⣿⣿⣿⣿⣿⠟⣹⣿⡿⢿⣿⣿⣬⣶⣶⡶⠦⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⣢⣙⣻⢿⣿⣿⣿⠎⢸⣿⠕⢹⣿⣿⡿⣛⣥⣀⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠛⠿⡏⣿⡏⠿⢄⣜⣡⠞⠛⡽⣸⡿⣟⡋⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠾⠿⣿⠁⠀⡄⠀⠀⠰⠾⠿⠛⠓⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠠⢐⢉⢷⣀⠛⠠⠐⠐⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣠⣴⣶⣿⣧⣾⠡⠼⠎⢎⣋⡄⠆⠀⠱⡄⢉⠃⣦⡤⡀⠀⠀⠀⠀
⠀⠀⠐⠙⠻⢿⣿⣿⣿⣿⣿⣿⣄⡀⠀⢩⠀⢀⠠⠂⢀⡌⠀⣿⡇⠟⠀⠀⢄⠀
⠀⣴⣇⠀⡇⠀⠸⣿⣿⣿⣿⣽⣟⣲⡤⠀⣀⣠⣴⡾⠟⠀⠀⠟⠀⠀⠀⠀⡰⡀
⣼⣿⠋⢀⣇⢸⡄⢻⣟⠻⣿⣿⣿⣿⣿⣿⠿⡿⠟⢁⠀⠀⠀⠀⠀⢰⠀⣠⠀⠰
⢸⣿⡣⣜⣿⣼⣿⣄⠻⡄⡀⠉⠛⠿⠿⠛⣉⡤⠖⣡⣶⠁⠀⠀⠀⣾⣶⣿⠐⡀
⣾⡇⠈⠛⠛⠿⣿⣿⣦⠁⠘⢷⣶⣶⡶⠟⢋⣠⣾⡿⠃⠀⠀⠀⠰⠛⠉⠉⠀⠀

  ZERO TRUST NETWORK ACCESS (ZTNA)  |  Never Trust, Always Verify
  Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan
"""

# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
    return hmac.compare_digest(dk.hex(), dk_hex)


def totp(secret_b32: str, at: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32)
    counter = int((at if at is not None else time.time()) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    now = time.time()
    return any(
        hmac.compare_digest(totp(secret_b32, now + i * 30), code)
        for i in range(-window, window + 1)
    )


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class User:
    username: str
    password_hash: str
    totp_secret: str
    role: str
    disabled: bool = False


@dataclass
class DevicePosture:
    device_id: str
    os_patched: bool = False
    disk_encrypted: bool = False
    firewall_on: bool = False
    edr_running: bool = False
    jailbroken: bool = False

    def score(self) -> int:
        """0-100 trust score. Jailbroken/rooted devices are always 0."""
        if self.jailbroken:
            return 0
        pts = {"os_patched": 30, "disk_encrypted": 30, "firewall_on": 15, "edr_running": 25}
        return sum(v for k, v in pts.items() if getattr(self, k))


@dataclass
class Policy:
    resource: str
    allowed_roles: set
    min_device_score: int = 70
    max_risk: int = 50
    hours: tuple = (0, 24)          # allowed hour-of-day window [start, end)
    description: str = ""


@dataclass
class Decision:
    allow: bool
    reason: str
    risk: int = 0


# --------------------------------------------------------------------------
# Tamper-evident audit log (hash chain)
# --------------------------------------------------------------------------

class AuditLog:
    def __init__(self, path: Optional[str] = None):
        self.entries = []
        self.path = path
        self._last = "0" * 64

    def log(self, event: str, **fields):
        rec = {"ts": round(time.time(), 3), "event": event, **fields, "prev": self._last}
        digest = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        rec["hash"] = digest
        self._last = digest
        self.entries.append(rec)
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for rec in self.entries:
            body = {k: v for k, v in rec.items() if k != "hash"}
            if body["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != rec["hash"]:
                return False
            prev = rec["hash"]
        return True


# --------------------------------------------------------------------------
# Policy engine (deny by default, risk-adaptive)
# --------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self):
        self.policies: dict[str, Policy] = {}

    def add(self, policy: Policy):
        self.policies[policy.resource] = policy

    def evaluate(self, role: str, posture: DevicePosture, login_ip: str,
                 current_ip: str, resource: str, hour: Optional[int] = None) -> Decision:
        policy = self.policies.get(resource)
        if policy is None:
            return Decision(False, "no policy for resource (default deny)", 100)

        if role not in policy.allowed_roles:
            return Decision(False, f"role '{role}' not authorised for {resource}", 100)

        score = posture.score()
        if score < policy.min_device_score:
            return Decision(False, f"device trust {score} < required {policy.min_device_score}", 100 - score)

        hour = time.localtime().tm_hour if hour is None else hour
        start, end = policy.hours
        risk = 100 - score
        if not (start <= hour < end):
            return Decision(False, f"outside allowed hours {start}:00-{end}:00", max(risk, 60))
        if current_ip != login_ip:
            risk += 30  # network context changed mid-session
        if hour < 6 or hour >= 22:
            risk += 10

        if risk > policy.max_risk:
            return Decision(False, f"risk {risk} exceeds limit {policy.max_risk}", risk)
        return Decision(True, "all checks passed", risk)


# --------------------------------------------------------------------------
# Token service (short-lived, signed, device-bound, revocable)
# --------------------------------------------------------------------------

class TokenService:
    def __init__(self, key: bytes, ttl: int = 900):
        self.key, self.ttl = key, ttl
        self.revoked: set[str] = set()

    def issue(self, user: User, device_id: str, ip: str) -> str:
        now = int(time.time())
        payload = {"sub": user.username, "role": user.role, "dev": device_id,
                   "ip": ip, "iat": now, "exp": now + self.ttl, "jti": secrets.token_hex(8)}
        body = b64e(json.dumps(payload).encode())
        sig = b64e(hmac.new(self.key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str) -> Optional[dict]:
        try:
            body, sig = token.split(".")
            expect = b64e(hmac.new(self.key, body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, expect):
                return None
            payload = json.loads(b64d(body))
        except Exception:
            return None
        if payload["exp"] < time.time() or payload["jti"] in self.revoked:
            return None
        return payload

    def revoke(self, token: str):
        p = self.verify(token)
        if p:
            self.revoked.add(p["jti"])


# --------------------------------------------------------------------------
# ZTNA gateway
# --------------------------------------------------------------------------

class ZTNAGateway:
    MAX_FAILS, LOCK_SECONDS = 5, 300

    def __init__(self, audit_path: Optional[str] = None):
        self.users: dict[str, User] = {}
        self.engine = PolicyEngine()
        self.tokens = TokenService(os.environ.get("ZTNA_SECRET", secrets.token_hex(32)).encode())
        self.audit = AuditLog(audit_path)
        self.fails: dict[str, list] = {}
        self.resources: dict[str, callable] = {}

    # -- administration -----------------------------------------------------
    def add_user(self, username: str, password: str, role: str) -> str:
        secret = base64.b32encode(os.urandom(10)).decode()
        self.users[username] = User(username, hash_password(password), secret, role)
        self.audit.log("user_created", user=username, role=role)
        return secret

    def register_resource(self, name: str, handler, policy: Policy):
        self.resources[name] = handler
        self.engine.add(policy)

    # -- authentication -----------------------------------------------------
    def _locked(self, username: str) -> bool:
        now = time.time()
        recent = [t for t in self.fails.get(username, []) if now - t < self.LOCK_SECONDS]
        self.fails[username] = recent
        return len(recent) >= self.MAX_FAILS

    def login(self, username: str, password: str, otp: str,
              posture: DevicePosture, ip: str) -> tuple[bool, str]:
        user = self.users.get(username)
        if self._locked(username):
            self.audit.log("login_blocked_lockout", user=username, ip=ip)
            return False, "account temporarily locked"

        # Same generic error for every failure to avoid user enumeration.
        generic = "authentication failed"
        if not user:
            hash_password(password)  # equalise timing
            self.audit.log("login_failed", user=username, ip=ip, why="unknown user")
            return False, generic
        if user.disabled or not verify_password(password, user.password_hash) \
                or not verify_totp(user.totp_secret, otp):
            self.fails.setdefault(username, []).append(time.time())
            self.audit.log("login_failed", user=username, ip=ip, why="credentials/mfa")
            return False, generic
        if posture.score() == 0:
            self.audit.log("login_denied_device", user=username, device=posture.device_id)
            return False, "device not trusted"

        token = self.tokens.issue(user, posture.device_id, ip)
        self.fails.pop(username, None)
        self.audit.log("login_ok", user=username, ip=ip, device=posture.device_id,
                       device_score=posture.score())
        return True, token

    # -- per-request authorisation (continuous verification) -----------------
    def access(self, token: str, resource: str, posture: DevicePosture,
               ip: str, hour: Optional[int] = None) -> tuple[bool, str]:
        claims = self.tokens.verify(token)
        if not claims:
            self.audit.log("access_denied", resource=resource, why="invalid/expired token")
            return False, "invalid or expired session"
        if claims["dev"] != posture.device_id:
            self.tokens.revoke(token)
            self.audit.log("session_revoked", user=claims["sub"], why="device mismatch")
            return False, "token not valid for this device (session revoked)"

        d = self.engine.evaluate(claims["role"], posture, claims["ip"], ip, resource, hour)
        self.audit.log("access_allowed" if d.allow else "access_denied",
                       user=claims["sub"], resource=resource, ip=ip,
                       reason=d.reason, risk=d.risk)
        if not d.allow:
            return False, d.reason
        return True, self.resources[resource](claims["sub"])


# --------------------------------------------------------------------------
# HTTP front end
# --------------------------------------------------------------------------

def make_handler(gw: ZTNAGateway):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _posture(self, src: dict) -> DevicePosture:
            fields = {k: src.get(k, False) for k in
                      ("os_patched", "disk_encrypted", "firewall_on", "edr_running", "jailbroken")}
            return DevicePosture(device_id=str(src.get("device_id", "")), **fields)

        def do_POST(self):  # POST /login
            if self.path != "/login":
                return self._send(404, {"error": "not found"})
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 8192)
                body = json.loads(self.rfile.read(n))
                ok, res = gw.login(body["username"], body["password"], body["otp"],
                                   self._posture(body.get("device", {})), self.client_address[0])
            except Exception:
                return self._send(400, {"error": "bad request"})
            self._send(200 if ok else 401, {"token": res} if ok else {"error": res})

        def do_GET(self):  # GET /resource/<name>  (Bearer token + X-Device header)
            if not self.path.startswith("/resource/"):
                return self._send(404, {"error": "not found"})
            token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            try:
                dev = json.loads(self.headers.get("X-Device", "{}"))
            except Exception:
                return self._send(400, {"error": "bad device header"})
            ok, res = gw.access(token, self.path.split("/", 2)[2],
                                self._posture(dev), self.client_address[0])
            self._send(200 if ok else 403, {"data": res} if ok else {"error": res})

        def log_message(self, *a):
            pass

    return Handler


# --------------------------------------------------------------------------
# Sample deployment + demo
# --------------------------------------------------------------------------

def build_gateway() -> tuple[ZTNAGateway, dict]:
    gw = ZTNAGateway(audit_path="ztna_audit.log")
    secrets_map = {
        "alice": gw.add_user("alice", "Alice#Str0ng!Pass", "engineer"),
        "bob": gw.add_user("bob", "B0b#Finance!Pass", "finance"),
        "root": gw.add_user("root", "R00t#Admin!Pass", "admin"),
    }
    gw.register_resource("git", lambda u: f"[git-server] repo access for {u}",
                         Policy("git", {"engineer", "admin"}, min_device_score=70))
    gw.register_resource("payroll", lambda u: f"[payroll-db] salary data for {u}",
                         Policy("payroll", {"finance", "admin"}, min_device_score=85,
                                max_risk=30, hours=(8, 18)))
    gw.register_resource("admin-console", lambda u: f"[admin-console] welcome {u}",
                         Policy("admin-console", {"admin"}, min_device_score=100, max_risk=10))
    return gw, secrets_map


def demo():
    print(BANNER)
    gw, sec = build_gateway()
    good = DevicePosture("laptop-01", True, True, True, True)
    weak = DevicePosture("laptop-01", True, False, False, False)    # same device, posture degraded
    noedr = DevicePosture("laptop-01", True, True, True, False)     # same device, EDR stopped
    rooted = DevicePosture("phone-03", True, True, True, True, jailbroken=True)

    def show(title, ok, msg):
        print(f"  [{'ALLOW' if ok else 'DENY '}] {title}: {msg}")

    print("\n=== Identity & MFA ===")
    show("alice, wrong password", *gw.login("alice", "wrong", totp(sec["alice"]), good, "10.0.0.5"))
    show("alice, wrong OTP", *gw.login("alice", "Alice#Str0ng!Pass", "000000", good, "10.0.0.5"))
    show("alice on jailbroken device", *gw.login("alice", "Alice#Str0ng!Pass", totp(sec["alice"]), rooted, "10.0.0.5"))
    ok, tok = gw.login("alice", "Alice#Str0ng!Pass", totp(sec["alice"]), good, "10.0.0.5")
    show("alice, valid login", ok, "token issued" if ok else tok)

    print("\n=== Least privilege & device trust ===")
    show("alice -> git (healthy device)", *gw.access(tok, "git", good, "10.0.0.5", hour=10))
    show("alice -> payroll (wrong role)", *gw.access(tok, "payroll", good, "10.0.0.5", hour=10))
    show("alice -> unknown resource", *gw.access(tok, "secret-vault", good, "10.0.0.5", hour=10))
    show("alice -> git (device degraded)", *gw.access(tok, "git", weak, "10.0.0.5", hour=10))

    print("\n=== Continuous verification ===")
    show("alice -> git (EDR stopped, same IP)", *gw.access(tok, "git", noedr, "10.0.0.5", hour=10))
    show("alice -> git (EDR stopped + IP changed)", *gw.access(tok, "git", noedr, "203.0.113.9", hour=10))
    show("alice -> git (token from other device)", *gw.access(tok, "git", DevicePosture("evil", True, True, True, True), "10.0.0.5", hour=10))
    show("alice -> git (revoked session)", *gw.access(tok, "git", good, "10.0.0.5", hour=10))

    print("\n=== Time-bound access ===")
    ok, btok = gw.login("bob", "B0b#Finance!Pass", totp(sec["bob"]), good, "10.0.0.7")
    show("bob -> payroll at 10:00", *gw.access(btok, "payroll", good, "10.0.0.7", hour=10))
    show("bob -> payroll at 23:00", *gw.access(btok, "payroll", good, "10.0.0.7", hour=23))

    print("\n=== Brute-force lockout ===")
    for _ in range(5):
        gw.login("root", "guess", "000000", good, "198.51.100.4")
    show("root, correct creds after 5 failures", *gw.login("root", "R00t#Admin!Pass", totp(sec["root"]), good, "198.51.100.4"))

    print("\n=== Audit trail ===")
    print(f"  entries: {len(gw.audit.entries)} | chain intact: {gw.audit.verify_chain()}")
    gw.audit.entries[2]["user"] = "tampered"
    print(f"  after tampering with entry #2 -> chain intact: {gw.audit.verify_chain()}")


def serve(host="127.0.0.1", port=8443):
    print(BANNER)
    gw, sec = build_gateway()
    print("Demo TOTP secrets (load into an authenticator app):")
    for u, s in sec.items():
        print(f"  {u}: {s}")
    print(f"\nGateway listening on http://{host}:{port}  (put behind TLS in production)")
    print("  POST /login           {username,password,otp,device:{device_id,os_patched,...}}")
    print("  GET  /resource/<name> Authorization: Bearer <token>   X-Device: {...}\n")
    HTTPServer((host, port), make_handler(gw)).serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "demo"
    serve() if mode == "serve" else demo()
