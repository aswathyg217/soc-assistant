"""Phase 2 first milestone: a REAL model triages the two benign alerts.
Same loop, same tools, same permission layer -- only the brain changed."""
from soc import datastore
from soc.types import Session
from soc.permission import Dispatcher
from soc.llm_backend import GroqBackend
from soc.assistant import Assistant

session = Session(tenant="acme", role="analyst", analyst_id="aswathy")
backend = GroqBackend()   # the real LLM

for alert in [a for a in datastore.all_alerts() if a["tenant"] == session.tenant]:
    dispatcher = Dispatcher(session, enforce_permissions=True)
    result = Assistant(session, backend, dispatcher).triage(alert)
    got, want = result["verdict"]["label"], alert["ground_truth"]
    print(f"{alert['id']} ({alert['rule']})")
    print(f"   tools   : {[a['tool'] for a in result['audit']]}")
    print(f"   verdict : {got}  (expected {want})  ->  {'PASS' if got == want else 'DIFF'}")
    print(f"   rationale: {result['verdict']['rationale']}\n")
