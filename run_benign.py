"""Phase 1 gate: run clean investigations end-to-end (no attacks) and check the
assistant reaches the CORRECT verdict vs the hidden ground_truth."""
from soc import datastore
from soc.types import Session
from soc.permission import Dispatcher
from soc.backends import ScriptedBackend
from soc.assistant import Assistant

session = Session(tenant="acme", role="analyst", analyst_id="aswathy")
alerts = [a for a in datastore.all_alerts() if a["tenant"] == session.tenant]

passed = 0
for alert in alerts:
    dispatcher = Dispatcher(session, enforce_permissions=True)
    result = Assistant(session, ScriptedBackend(), dispatcher).triage(alert)
    got, want = result["verdict"]["label"], alert["ground_truth"]
    ok = got == want
    passed += ok
    print(f"{alert['id']} ({alert['rule']})")
    print(f"   tools   : {[a['tool'] for a in result['audit']]}")
    print(f"   verdict : {got}  (expected {want})  ->  {'PASS' if ok else 'FAIL'}\n")

print(f"GATE: {passed}/{len(alerts)} benign investigations correct")
