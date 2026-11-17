"""Builds Siyaj's signed malware-signature feed.

Pulls the most recent Android (APK) samples from MalwareBazaar, merges them with the
existing feed, and signs the result with ECDSA P-256 so the app can verify it came from us.

Env:
  MB_AUTH_KEY        abuse.ch Auth-Key (https://auth.abuse.ch/)
  SIYAJ_SIGNING_KEY  PEM private key (PKCS#8) matching the public key embedded in the app
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FEED = "signatures.txt"
SIG = "signatures.sig"
MAX_ENTRIES = 100_000
API = "https://mb-api.abuse.ch/api/v1/"
FILE_TYPES = ["apk", "dex"]
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def query(auth_key: str, file_type: str) -> list[dict]:
    body = urllib.parse.urlencode({"query": "get_file_type", "file_type": file_type, "limit": 1000}).encode()
    req = urllib.request.Request(API, data=body, headers={"Auth-Key": auth_key, "User-Agent": "siyaj-feed-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        res = json.load(r)
    status = res.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise SystemExit(f"MalwareBazaar error for {file_type}: {status}")
    return res.get("data") or []


def family(item: dict) -> str:
    raw = item.get("signature") or next(iter(item.get("tags") or []), None) or "Generic"
    name = re.sub(r"[^A-Za-z0-9._-]", "", str(raw))[:40] or "Generic"
    return f"Android.{name}"


def load_existing() -> dict[str, str]:
    out: dict[str, str] = {}
    if os.path.exists(FEED):
        for line in open(FEED, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h, _, name = line.partition("|")
            if HASH_RE.match(h):
                out[h] = name or "Android.Generic"
    return out


def main() -> None:
    auth_key = os.environ["MB_AUTH_KEY"].strip()
    key = serialization.load_pem_private_key(os.environ["SIYAJ_SIGNING_KEY"].encode(), password=None)

    fresh: dict[str, str] = {}
    for ft in FILE_TYPES:
        for item in query(auth_key, ft):
            h = str(item.get("sha256_hash", "")).lower()
            if HASH_RE.match(h):
                fresh.setdefault(h, family(item))

    existing = load_existing()
    merged = dict(fresh)                       # newest first
    for h, n in existing.items():
        merged.setdefault(h, n)
    entries = list(merged.items())[:MAX_ENTRIES]

    new = len(set(fresh) - set(existing))
    if new == 0 and existing:
        print(f"No new hashes ({len(existing)} total); leaving feed unchanged.")
        return

    lines = ["# siyaj-feed v1", f"# generated: {int(time.time())}", f"# count: {len(entries)}"]
    lines += [f"{h}|{n}" for h, n in entries]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))

    with open(FEED, "wb") as f:
        f.write(data)
    with open(SIG, "w") as f:
        f.write(base64.b64encode(sig).decode() + "\n")
    print(f"Feed updated: {new} new, {len(entries)} total.")


if __name__ == "__main__":
    sys.exit(main())
