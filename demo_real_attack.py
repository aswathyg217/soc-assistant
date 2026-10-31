"""Triage a REAL brute-force: Hydra attacked Kali's sshd, sshd logged it,
scripts/ingest_real_ssh.py shipped the lines to Splunk. This reads the evidence
live from Splunk and classifies it.

It discovers the MOST RECENT ingest run (by replay_run) and triages that run's
events, so it always matches whatever ingest just produced — no hardcoded ids.

Run with:  SOC_LOG_BACKEND=splunk python demo_real_attack.py
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
USER, PW = os.getenv("SPLUNK_USER", "admin"), os.getenv("SPLUNK_PASSWORD", "")
INDEX = os.getenv("SPLUNK_INDEX", "soc_logs")
TENANT = os.getenv("SOC_TENANT", "acme")
TLS = ds._tls_setting()
_store = SplunkLogStore(URL, USER, PW, INDEX, **TLS)
verify = _store._verify_arg()

# Find the latest real-ssh ingest run and its event ids (tenant-scoped, bounded).
spl = (f'search index={INDEX} earliest=-7d latest=now | spath '
       f'| search tenant="{TENANT}" action=ssh_login_failed id="real-ssh-*" '
       '| stats latest(replay_ts) as rt values(id) as ids by replay_run '
       '| sort - rt | head 1')
r = requests.post(f"{URL}/services/search/jobs/export", auth=(USER, PW), verify=verify,
                  timeout=60, data={"search": spl, "output_mode": "json", "exec_mode": "oneshot"})
r.raise_for_status()
rows = [json.loads(l)["result"] for l in r.text.splitlines() if l.strip() and "result" in json.loads(l)]
if not rows:
    print("No real-ssh events found in Splunk. Run scripts/ingest_real_ssh.py first.")
    raise SystemExit(0)
ids = rows[0]["ids"]
ids = ids if isinstance(ids, list) else [ids]
print(f"Triaging real ingest run {rows[0]['replay_run']} with {len(ids)} failed-login events.\n")

ds.use_store(_store)
REAL_ALERT = {"id": "ALR-REAL-1", "tenant": TENANT,
              "rule": "Repeated failed SSH logins (possible brute force)",
              "severity": "high", "status": "open", "related_log_ids": ids,
              "analyst_task": "Decide whether this alert is a true positive or benign.",
              "ground_truth": "true_positive"}
_orig = ds.get_alert
ds.get_alert = lambda aid: REAL_ALERT if aid == "ALR-REAL-1" else _orig(aid)

session = Session(TENANT, "analyst", "aswathy")
d = Dispatcher(session, enforce_permissions=True)
result = Assistant(session, GroqBackend(), d).triage(REAL_ALERT)
print("Evidence pulled from Splunk; tools called:", [e["tool"] for e in d.audit])
print("Verdict   :", result["verdict"]["label"], "(expected true_positive)")
print("Rationale :", result["verdict"]["rationale"])
