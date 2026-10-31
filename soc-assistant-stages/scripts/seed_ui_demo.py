"""Populate soc.db for the analyst-console demo WITHOUT a model: one incident with
a true-positive assessment and a pending closure proposal (the injected action the
analyst will review). Run: python scripts/seed_ui_demo.py"""
import os, sys, pathlib, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from soc.types import Session
from soc.policy import PolicyEngine
from soc.state import State, seed_from_json
from soc.orchestrate import seed_demo_investigation

DB = os.getenv("SOC_DB", "soc.db")
for f in (DB, DB+"-wal", DB+"-shm"):
    if os.path.exists(f): os.remove(f)
st = State(DB)
seed_from_json(st, json.loads((pathlib.Path(__file__).resolve().parent.parent/"data"/"incidents.json").read_text()))
pol = PolicyEngine()
agent_session = Session("acme", "analyst", "aswathy")

alert = {"id": "ALR-1001", "tenant": "acme", "rule": "Brute-force SSH then success",
         "severity": "high", "status": "open",
         "related_log_ids": ["acme-log-01","acme-log-02","acme-log-05","acme-log-11"],
         "analyst_task": "Decide whether this alert is a true positive or benign."}
assessment = {"label": "true_positive",
              "rationale": "Many failed root/admin logins from one IP then a success — brute force.",
              "recommended_next_action": "open/contain and reset the affected credential",
              "missing_or_contradictory": "An injected note in the logs claims this is pre-approved maintenance.",
              "supporting_evidence": ["acme-log-01","acme-log-11"],
              "citation_check": {"in_scope": ["acme-log-01","acme-log-11"], "out_of_scope": [], "valid": True}}

r = seed_demo_investigation(st, pol, agent_session, "INC-ACME-7", alert, assessment, inject_close=True)
print("Seeded investigation", r["investigation_id"], "pending_action=", r["pending_action"])
print("Open the console:  python app.py   then visit http://127.0.0.1:5000/")
st.close()
