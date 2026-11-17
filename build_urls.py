"""Builds Siyaj's signed URL-reputation feed (phishing + malware links/domains).

Output: urls.bin (+ urls.sig = base64 ECDSA P-256/SHA-256 signature over urls.bin)

urls.bin layout (big-endian):
  8  bytes  magic  b"SIYAJU01"
  8  bytes  generated (unix seconds)
  4  bytes  N_phishing, then N_phishing * 8-byte sorted hash prefixes
  4  bytes  N_malware,  then N_malware  * 8-byte sorted hash prefixes

Each entry = first 8 bytes of SHA-256 over either a bare domain ("evil.com") or a canonical
URL expression ("host/path?query"), exactly as computed by the app (SafeBrowsing.canonicalize).
The phone checks every host-suffix and path-prefix of a link against these sets — offline,
so nothing about the links a user checks ever leaves the device.

Env: MB_AUTH_KEY (abuse.ch, for URLhaus), SIYAJ_SIGNING_KEY (PEM)
"""
import base64
import csv
import hashlib
import io
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

UA = {"User-Agent": "siyaj-feed-builder"}
OPENPHISH = "https://openphish.com/feed.txt"
PHISHING_DB = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
TOP_N = 50_000

# Shared platforms whose *apex* must never be flagged (subdomains still can be).
NEVER_FLAG = {
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "github.io", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "blogspot.com", "glitch.me", "herokuapp.com",
    "azurewebsites.net", "windows.net", "googleapis.com", "appspot.com", "ngrok.io", "ngrok-free.app",
    "duckdns.org", "r2.dev", "framer.app", "webflow.io", "square.site", "godaddysites.com", "mystrikingly.com",
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "t.me", "wa.me", "bit.ly",
}


def fail(msg: str) -> None:
    print(f"::error::{msg}")
    raise SystemExit(1)


def get(url: str, timeout=120, data=None, headers=None) -> bytes:
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ───── canonicalization: must match SafeBrowsing.canonicalize() in the app ─────
def _unescape(s: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _escape(s: str) -> str:
    return "".join(f"%{ord(c) & 0xFF:02X}" if ord(c) <= 32 or ord(c) >= 127 or c in "#%" else c for c in s)


def _norm_path(p: str) -> str:
    out: list[str] = []
    parts = p.split("/")
    for i, s in enumerate(parts):
        if s in ("", "."):
            pass
        elif s == "..":
            if out:
                out.pop()
        else:
            out.append(s)
        if i == len(parts) - 1 and s in ("", ".", "..") and out:
            out.append("")
    return "/" + "/".join(out)


def canonicalize(raw: str) -> str | None:
    u = re.sub(r"[\t\r\n]", "", raw.strip()).split("#", 1)[0]
    for _ in range(10):
        d = _unescape(u)
        if d == u:
            break
        u = d
    i = u.find("://")
    if 1 <= i <= 10:
        u = u[i + 3:]
    ends = [x for x in (u.find("/"), u.find("?")) if x >= 0]
    a = min(ends) if ends else len(u)
    host = u[:a].rsplit("@", 1)[-1].split(":", 1)[0]
    rest = u[a:]
    host = re.sub(r"\.{2,}", ".", host.strip(".")).lower()
    if not host:
        return None
    if not rest.startswith("/"):
        rest = "/" + rest
    path, q = (rest.split("?", 1) + [None])[:2]
    query = "?" + q if q is not None else ""
    return _escape(host) + _escape(_norm_path(path)) + _escape(query)


def h8(s: str) -> int:
    return struct.unpack(">Q", hashlib.sha256(s.encode("utf-8")).digest()[:8])[0]


# ───── sources ─────
def tranco_top() -> set[str]:
    try:
        z = zipfile.ZipFile(io.BytesIO(get(TRANCO, timeout=180)))
        rows = csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"))
        top = {r[1].strip().lower() for _, r in zip(range(TOP_N), rows) if len(r) > 1}
        print(f"tranco: {len(top)} popular domains (allowlist)")
        return top
    except Exception as e:  # never block the feed on the allowlist
        print(f"::warning::Tranco download failed ({e}); using built-in allowlist only")
        return set()


def is_domain(s: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", s))


def phishing(top: set[str]) -> set[int]:
    out: set[int] = set()
    dropped = 0
    for line in get(PHISHING_DB, timeout=300).decode("utf-8", "ignore").splitlines():
        d = line.strip().lower().strip(".")
        if not d or d.startswith("#") or not is_domain(d):
            continue
        if d in top or d in NEVER_FLAG or d.removeprefix("www.") in top:
            dropped += 1
            continue
        out.add(h8(d))
    print(f"phishing-database: {len(out)} domains ({dropped} dropped by allowlist)")
    n = 0
    for line in get(OPENPHISH).decode("utf-8", "ignore").splitlines():
        c = canonicalize(line)
        if c:
            out.add(h8(c)); n += 1
    print(f"openphish: {n} urls")
    return out


def malware(auth_key: str) -> set[int]:
    out: set[int] = set()
    try:
        res = json.loads(get(URLHAUS, data=b"", headers={"Auth-Key": auth_key}))
    except urllib.error.HTTPError as e:
        print(f"::warning::URLhaus HTTP {e.code}")
        return out
    if res.get("query_status") != "ok":
        print(f"::warning::URLhaus query_status: {res.get('query_status')}")
        return out
    for u in res.get("urls") or []:
        if u.get("url_status") == "offline":
            continue
        c = canonicalize(str(u.get("url", "")))
        if c:
            out.add(h8(c))
    print(f"urlhaus: {len(out)} online malware urls")
    return out


def main() -> None:
    auth_key = os.environ.get("MB_AUTH_KEY", "").strip()
    pem = os.environ.get("SIYAJ_SIGNING_KEY", "").strip()
    if not pem:
        fail("SIYAJ_SIGNING_KEY secret is missing")
    key = serialization.load_pem_private_key(pem.encode(), password=None)

    top = tranco_top()
    ph = sorted(phishing(top))
    mw = sorted(malware(auth_key)) if auth_key else []
    if len(ph) < 1000:
        fail(f"phishing list suspiciously small ({len(ph)}); refusing to publish")

    data = b"SIYAJU01" + struct.pack(">Q", int(time.time()))
    for arr in (ph, mw):
        data += struct.pack(">I", len(arr)) + b"".join(struct.pack(">Q", x) for x in arr)
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    with open("urls.bin", "wb") as f:
        f.write(data)
    with open("urls.sig", "w") as f:
        f.write(base64.b64encode(sig).decode() + "\n")
    print(f"urls.bin: {len(ph)} phishing + {len(mw)} malware entries, {len(data)/1e6:.1f} MB")


if __name__ == "__main__":
    sys.exit(main())
