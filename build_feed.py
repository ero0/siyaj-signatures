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
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FEED = "signatures.txt"
SIG = "signatures.sig"
MAX_ENTRIES = 100_000
API = "https://mb-api.abuse.ch/api/v1/"
FILE_TYPES = ["apk", "dex"]
# Well-known Android malware families: pull their history too, not just the latest uploads.
FAMILIES = [
    "SpyNote", "Anatsa", "Hydra", "Cerberus", "Alien", "Hook", "ERMAC", "Octo", "Coper", "Xenomorph",
    "SharkBot", "TeaBot", "FluBot", "Joker", "Harly", "Konfety", "SpyMax", "AhMyth", "CraxsRAT", "Cypher",
    "IRATA", "BRATA", "Vultur", "GodFather", "Chameleon", "BianLian", "Medusa", "TgToxic", "Rafel", "Mirai",
    "PixPirate", "Rokrat", "DeathRAT", "SpinOk", "Necro", "Triada", "Anubis", "Gigabud", "MoqHao", "Copybara",
]
GENERIC_TAGS = {"apk", "dex", "android", "elf", "zip", "jar", "malware", "trojan", "rat", "banker", "spyware", "signed", "unsigned"}
IP_RE = re.compile(r"^\d{1,3}([.-]\d{1,3}){3}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(msg: str) -> None:
    print(f"::error::{msg}")
    raise SystemExit(1)


def query(auth_key: str, file_type: str) -> list[dict]:
    return api(auth_key, {"query": "get_file_type", "file_type": file_type, "limit": 1000}, file_type)


def api(auth_key: str, params: dict, label: str) -> list[dict]:
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API, data=body, headers={"Auth-Key": auth_key, "User-Agent": "siyaj-feed-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        res = json.load(r)
    status = res.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        print(f"::warning::MalwareBazaar query_status for {label}: {status}")
        return []
    return res.get("data") or []


def family(item: dict) -> str:
    def useful(t) -> bool:
        t = str(t).strip()
        return bool(t) and t.lower() not in GENERIC_TAGS and not IP_RE.match(t) and not t.lower().startswith(("http", "certificat"))
    raw = item.get("signature") if useful(item.get("signature") or "") else next((t for t in item.get("tags") or [] if useful(t)), None)
    name = re.sub(r"[^A-Za-z0-9._-]", "", str(raw or ""))[:40] or "Malware"
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
                n = name.removeprefix("Android.")
                if not n or n.lower() in GENERIC_TAGS or IP_RE.match(n) or n.lower().startswith("certificat"):
                    name = "Android.Malware"
                out[h] = name or "Android.Malware"
    return out


def main() -> None:
    auth_key = os.environ.get("MB_AUTH_KEY", "").strip()
    pem = os.environ.get("SIYAJ_SIGNING_KEY", "").strip()
    if not auth_key:
        fail("MB_AUTH_KEY secret is empty or missing (must be an Actions secret)")
    if not pem:
        fail("SIYAJ_SIGNING_KEY secret is empty or missing (must be an Actions secret)")
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except Exception as e:
        fail(f"SIYAJ_SIGNING_KEY is not a valid PEM private key ({type(e).__name__}); paste the whole file incl. BEGIN/END lines")

    fresh: dict[str, str] = {}
    for ft in FILE_TYPES:
        try:
            items = query(auth_key, ft)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                fail(f"MalwareBazaar rejected MB_AUTH_KEY (HTTP {e.code}); regenerate it at auth.abuse.ch")
            print(f"::warning::MalwareBazaar HTTP {e.code} for file_type={ft}")
            continue
        print(f"file_type={ft}: {len(items)} samples")
        for item in items:
            h = str(item.get("sha256_hash", "")).lower()
            if HASH_RE.match(h):
                fresh.setdefault(h, family(item))

    for fam in FAMILIES:
        try:
            items = api(auth_key, {"query": "get_siginfo", "signature": fam, "limit": 1000}, f"signature={fam}")
        except urllib.error.HTTPError as e:
            print(f"::warning::MalwareBazaar HTTP {e.code} for signature={fam}")
            continue
        apks = [i for i in items if str(i.get("file_type", "")).lower() in FILE_TYPES]
        print(f"signature={fam}: {len(apks)} android samples")
        for item in apks:
            h = str(item.get("sha256_hash", "")).lower()
            if HASH_RE.match(h):
                fresh.setdefault(h, f"Android.{fam}")
        time.sleep(0.5)  # be gentle with the free API

    if not fresh:
        fail("MalwareBazaar returned no samples for any file type (see warnings above)")
    existing = load_existing()
    merged = dict(fresh)                       # newest first
    for h, n in existing.items():
        merged.setdefault(h, n)
    entries = list(merged.items())[:MAX_ENTRIES]

    new = len(set(fresh) - set(existing))
    relabeled = any(existing.get(h) != n for h, n in entries if h in existing)
    if new == 0 and existing and not relabeled:
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
