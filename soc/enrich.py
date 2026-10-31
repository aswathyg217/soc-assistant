"""Optional enrichment: VirusTotal file-hash reputation for a file-related alert.

Safety properties:
- hashes are validated (md5/sha1/sha256) before any lookup;
- credentials stay server-side (VT_API_KEY env), never from the model or logs;
- lookup is GET-by-hash only -- files are NEVER uploaded;
- API/network failures return a structured error, not an exception;
- a clearly-labelled OFFLINE MOCK is the default, so the demo works with no key.

Select the live API with SOC_VT_MODE=live AND a VT_API_KEY in the environment;
otherwise the offline mock is used and every result says source='offline-mock'.
"""
import os, re

_HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")
_LENS = {32: "md5", 40: "sha1", 64: "sha256"}

# The EICAR anti-malware TEST file (harmless, industry-standard) stands in for a
# "known bad" hash in the offline demo. It is NOT real malware.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def validate_hash(h: str):
    if not isinstance(h, str):
        return None
    h = h.strip().lower()
    if _HASH_RE.match(h) and len(h) in _LENS:
        return h
    return None


class VirusTotalClient:
    """Live VirusTotal v3 lookup. GET by hash only; no uploads."""
    BASE = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key, timeout=15, verify_tls=True):
        self.api_key = api_key
        self.timeout = timeout
        self.verify = verify_tls

    def lookup(self, file_hash: str) -> dict:
        h = validate_hash(file_hash)
        if not h:
            return {"ok": False, "error": "invalid_hash"}
        import requests
        try:
            r = requests.get(self.BASE + h, headers={"x-apikey": self.api_key},
                             timeout=self.timeout, verify=self.verify)
        except requests.exceptions.RequestException as e:
            return {"ok": False, "error": f"network_error: {e}"}
        if r.status_code == 404:
            return {"ok": True, "found": False, "source": "virustotal", "hash": h}
        if r.status_code == 401:
            return {"ok": False, "error": "unauthorized (check VT_API_KEY)"}
        if r.status_code == 429:
            return {"ok": False, "error": "rate_limited"}
        if r.status_code != 200:
            return {"ok": False, "error": f"http_{r.status_code}"}
        try:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        except Exception:
            return {"ok": False, "error": "unexpected_response"}
        return {"ok": True, "found": True, "source": "virustotal", "hash": h,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)}


class MockReputation:
    """Offline, deterministic. Clearly labelled source='offline-mock'."""
    def lookup(self, file_hash: str) -> dict:
        h = validate_hash(file_hash)
        if not h:
            return {"ok": False, "error": "invalid_hash"}
        if h == EICAR_SHA256:
            return {"ok": True, "found": True, "source": "offline-mock", "hash": h,
                    "malicious": 62, "suspicious": 1, "harmless": 0, "undetected": 7,
                    "note": "EICAR test signature (harmless test file), mocked as malicious"}
        # deterministic split so other demo hashes return a stable verdict
        if h.endswith(("0", "1", "2", "3")):
            return {"ok": True, "found": True, "source": "offline-mock", "hash": h,
                    "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 2}
        return {"ok": True, "found": False, "source": "offline-mock", "hash": h}


def get_client():
    if os.getenv("SOC_VT_MODE", "mock").lower() == "live" and os.getenv("VT_API_KEY"):
        return VirusTotalClient(os.getenv("VT_API_KEY"))
    return MockReputation()


def reputation(file_hash: str) -> dict:
    return get_client().lookup(file_hash)
