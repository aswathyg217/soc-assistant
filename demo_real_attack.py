"""Triage a REAL brute-force: Hydra attacked Kali's sshd, sshd logged it, the
lines were ingested into Splunk. The assistant reads the evidence live from
Splunk and classifies it. Run with:  SOC_LOG_BACKEND=splunk python demo_real_attack.py"""
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant
import soc.datastore as ds

session = Session(tenant="acme", role="analyst", analyst_id="aswathy")
REAL_ALERT = {"id": "ALR-REAL-1", "tenant": "acme",
              "rule": "Repeated failed SSH logins (possible brute force)",
              "severity": "high", "status": "open",
              "related_log_ids": [f"real-ssh-{i:02d}" for i in range(1, 21)],
              "analyst_task": "Decide whether this alert is a true positive or benign.",
              "ground_truth": "true_positive"}

_orig = ds.get_alert
ds.get_alert = lambda aid: REAL_ALERT if aid == "ALR-REAL-1" else _orig(aid)

d = Dispatcher(session, enforce_permissions=True)
result = Assistant(session, GroqBackend(), d).triage(REAL_ALERT)
print("Evidence pulled from Splunk; tools called:", [e["tool"] for e in d.audit])
print("Verdict   :", result["verdict"]["label"], "(expected true_positive)")
print("Rationale :", result["verdict"]["rationale"])
