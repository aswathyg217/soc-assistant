"""Deterministic offline regression tests for Stage 1 baseline hardening.
No model, no network. Run:  python -m pytest tests/  (or: python tests/test_baseline.py)"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from soc.types import Session
from soc.permission import Dispatcher
from soc.tools import search_logs
from soc.logstore import JSONLogStore, _valid_tenant
import soc.datastore as ds

S = Session(tenant="acme", role="analyst", analyst_id="aswathy")


def test_cross_tenant_denied_under_c2():
    d = Dispatcher(S, enforce_permissions=True)
    r = d.call("get_incident_record", incident_id="INC-GLOBEX-9")
    assert not r.ok and "cross-tenant" in r.error


def test_cross_tenant_leaks_without_enforcement():
    d = Dispatcher(S, enforce_permissions=False)
    assert d.call("get_incident_record", incident_id="INC-GLOBEX-9").ok


def test_own_tenant_allowed():
    d = Dispatcher(S, enforce_permissions=True)
    assert d.call("get_incident_record", incident_id="INC-ACME-7").ok


def test_unknown_tool_denied():
    d = Dispatcher(S, enforce_permissions=True)
    assert not d.call("rm_rf", path="/").ok


def test_unknown_alert_id_errors_not_silent():
    r = search_logs(S, alert_id="ALR-NOPE")
    assert not r.ok and "unknown_alert" in r.error


def test_known_alert_scopes_to_its_logs():
    r = search_logs(S, alert_id="ALR-1001")
    assert r.ok and len(r.data) == 11 and all(l["tenant"] == "acme" for l in r.data)


def test_tenant_validation_rejects_injection():
    for bad in ['acme" | delete', "a b", "acme;", "../x", ""]:
        try:
            _valid_tenant(bad); assert False, f"accepted bad tenant {bad!r}"
        except ValueError:
            pass
    assert _valid_tenant("acme") == "acme"


def test_jsonstore_tenant_scope_and_cap():
    assert all(l["tenant"] == "globex" for l in JSONLogStore().all_logs(tenant="globex"))
    assert len(JSONLogStore().all_logs(max_count=2)) == 2


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for fn in fns:
        try:
            fn(); ok += 1; print(f"PASS {fn.__name__}")
        except Exception:
            print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{ok}/{len(fns)} passed")
    sys.exit(0 if ok == len(fns) else 1)
