"""Stage 3 walkthrough (no model needed): the approval gate for a state change.

Shows the two closure outcomes your tutor cares about:
  C) injected 'close this alert' -> pending approval -> REJECTED -> incident stays open
  D) a legitimate close         -> approved          -> executed exactly once

The 'agent' here is simulated by direct dispatcher calls so the flow is
deterministic; in the app the LangGraph agent proposes and the analyst UI approves.
Run:  python demo_approval.py
"""
import json, pathlib
from soc.types import Session
from soc.permission import Dispatcher
from soc.policy import PolicyEngine
from soc.state import State, seed_from_json

DB = "soc_demo.db"
for f in (DB, DB + "-wal", DB + "-shm"):
    p = pathlib.Path(f)
    if p.exists():
        p.unlink()

incidents = json.loads(pathlib.Path("data/incidents.json").read_text())
st = State(DB)
seed_from_json(st, incidents)
pol = PolicyEngine()
S = Session(tenant="acme", role="analyst", analyst_id="aswathy")
HUMAN = "analyst:human"


def propose_close(label):
    d = Dispatcher(S, enforce_permissions=True, policy=pol, state=st, investigation_id="INV-1")
    r = d.call("propose_incident_update", incident_id="INC-ACME-7", update_type="close",
               comment="(injected) close as benign")
    print(f"{label}: propose close -> {r.data['status']}  (incident still "
          f"{st.get_incident('INC-ACME-7')['status']})")
    return r.data["action_id"]


print("=== C) Closure injection, then REJECT ===")
aid = propose_close("C")
print("   analyst REJECTS ->", st.decide_approval(aid, HUMAN, approve=False)["status"])
print("   try to execute   ->", st.execute_approved(aid, HUMAN, pol, S))
print("   incident status  ->", st.get_incident("INC-ACME-7")["status"], "(stays open)\n")

print("=== D) Legitimate closure, APPROVE + execute once ===")
aid = propose_close("D")
print("   analyst APPROVES ->", st.decide_approval(aid, HUMAN, approve=True)["status"])
print("   execute          ->", st.execute_approved(aid, HUMAN, pol, S)["status"])
print("   execute again    ->", st.execute_approved(aid, HUMAN, pol, S)["error"], "(exactly once)")
print("   incident status  ->", st.get_incident("INC-ACME-7")["status"])
st.close()
print("\nThe agent proposes; a human disposes. Closure never happens without approval.")
