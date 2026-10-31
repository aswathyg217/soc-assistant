"""Stage 6 demo: enrich a file-related alert with VirusTotal (offline mock by
default; set SOC_VT_MODE=live + VT_API_KEY for the real API). The reputation tool
goes through the same policy gateway as every other tool.

Run:  python demo_virustotal.py
"""
from soc.types import Session
from soc.permission import Dispatcher
from soc.policy import PolicyEngine
from soc.enrich import EICAR_SHA256

session = Session("acme", "analyst", "aswathy")
pol = PolicyEngine()
d = Dispatcher(session, enforce_permissions=True, policy=pol)

print("File-related alert: suspicious attachment hash seen on an endpoint.")
for label, h in [("flagged attachment", EICAR_SHA256), ("invalid hash", "not-a-hash")]:
    r = d.call("get_file_reputation", file_hash=h)
    print(f"\n{label}: {h[:16]}...")
    print("  ->", r.data if r.ok else f"error: {r.error}")
print("\nEvery lookup was authorized by the policy gateway; no file was uploaded.")
