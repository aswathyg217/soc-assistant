"""Splunk does the detecting: a bounded, tenant-scoped correlation search builds a
CANDIDATE alert from failed-login volume, and the assistant then triages it under
the permission layer. The count threshold is a DETECTION HEURISTIC that raises a
candidate — not ground truth that the alert is malicious; the assistant still has
to investigate the evidence and decide.

TLS verified by default; set SPLUNK_CA_CERT or SPLUNK_VERIFY_TLS=0 for a local lab.
Run with the splunk backend, e.g.:  SOC_LOG_BACKEND=splunk python demo_splunk_detect.py
"""
import os, json, requests
from dotenv import load_dotenv
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant
from soc.logstore import SplunkLogStore
import soc.datastore as ds

load_dotenv()
URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
USER = os.getenv("SPLUNK_USER", "admin")
PW = os.getenv("SPLUNK_PASSWORD", "")
INDEX = os.getenv("SPLUNK_INDEX", "soc_logs")
TENANT = os.getenv("SOC_TENANT", "acme")
THRESHOLD = int(os.getenv("SOC_BRUTE_THRESHOLD", "5"))
EARLIEST, LATEST = os.getenv("SOC_EARLIEST", "-24h"), os.getenv("SOC_LATEST", "now")

TLS = ds._tls_setting()                      # reuse the same verified-by-default policy
_store = SplunkLogStore(URL, USER, PW, INDEX, **TLS)

# Bounded (time window + head) and tenant-scoped (tenant is allowlist-validated in SPL).
DET = (f'search index={INDEX} earliest={EARLIEST} latest={LATEST} '
       f'| spath | search tenant="{TENANT}" action=ssh_login_failed '
       '| stats count values(id) as ids values(user) as users dc(user) as nusers by src_ip '
       f'| where count>={THRESHOLD} | sort - count | head 1')

r = requests.post(f"{URL}/services/search/jobs/export", auth=(USER, PW),
                  verify=_store._verify_arg(), timeout=60,
                  data={"search": DET, "output_mode": "json", "exec_mode": "oneshot"})
r.raise_for_status()
rows = [json.loads(l)["result"] for l in r.text.splitlines()
        if l.strip() and "result" in json.loads(l)]
if not rows:
    print(f"Splunk detected no brute-force candidate (>= {THRESHOLD} failures) for {TENANT}.")
    raise SystemExit(0)

det = rows[0]
ip, c = det["src_ip"], int(det["count"])
ids = det["ids"] if isinstance(det["ids"], list) else [det["ids"]]
print(f"SPLUNK DETECTION (candidate) -> {c} failed logins from {ip}, "
      f"{det.get('nusers')} usernames. Threshold {THRESHOLD} is a heuristic, not a verdict.\n")

ds.use_store(_store)
ALERT = {"id": "ALR-SPL-1", "tenant": TENANT,
         "rule": f"SSH brute-force candidate from {ip} ({c} failures) - raised by Splunk",
         "severity": "high", "status": "open", "related_log_ids": ids,
         "analyst_task": "Decide whether this alert is a true positive or benign.",
         "ground_truth": "true_positive"}
_o = ds.get_alert
ds.get_alert = lambda a: ALERT if a == "ALR-SPL-1" else _o(a)

s = Session(TENANT, "analyst", "aswathy")
d = Dispatcher(s, enforce_permissions=True)
res = Assistant(s, GroqBackend(), d).triage(ALERT)
print("Tools    :", [e["tool"] for e in d.audit])
print("Verdict  :", res["verdict"]["label"], "(expected true_positive)")
print("Rationale:", res["verdict"]["rationale"])
