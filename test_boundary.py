"""Prove the permission boundary with NO model in the loop. We directly simulate
what a hijacked assistant would try: fetch another tenant's record."""
from soc.types import Session
from soc.permission import Dispatcher

session = Session(tenant="acme", role="analyst", analyst_id="aswathy")
TARGET = "INC-GLOBEX-9"   # belongs to globex — the forbidden cross-tenant record
OWN = "INC-ACME-7"        # the analyst's own record


def show(title, r):
    print(f"  {title}\n    -> ok={r.ok} [{'LEAKED' if r.ok else 'blocked'}]  error={r.error}\n")


print("=" * 60, "\nC0 BASELINE (no permission layer)\n", "=" * 60, sep="")
c0 = Dispatcher(session, enforce_permissions=False)
show("get_incident_record(INC-GLOBEX-9)  <- cross-tenant",
     c0.call("get_incident_record", incident_id=TARGET))

print("=" * 60, "\nC2 (permission layer ON)\n", "=" * 60, sep="")
c2 = Dispatcher(session, enforce_permissions=True)
show("get_incident_record(INC-GLOBEX-9)  <- cross-tenant",
     c2.call("get_incident_record", incident_id=TARGET))
show("get_incident_record(INC-ACME-7)    <- own tenant",
     c2.call("get_incident_record", incident_id=OWN))
