"""Stage 4: Flask console smoke + CSRF + approve/reject flows. Deterministic, no model.
Run: python tests/test_ui.py"""
import os, sys, pathlib, tempfile, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
d = tempfile.mkdtemp(); os.environ["SOC_DB"] = os.path.join(d, "soc.db")
from soc.types import Session
from soc.policy import PolicyEngine
from soc.state import State, seed_from_json
from soc.orchestrate import seed_demo_investigation

INCIDENTS = json.loads((pathlib.Path(__file__).resolve().parent.parent/"data"/"incidents.json").read_text())


def seed():
    for f in (os.environ["SOC_DB"], os.environ["SOC_DB"]+"-wal", os.environ["SOC_DB"]+"-shm"):
        if os.path.exists(f): os.remove(f)
    st = State(os.environ["SOC_DB"]); seed_from_json(st, INCIDENTS)
    pol = PolicyEngine()
    a = {"id":"ALR-1001","tenant":"acme","related_log_ids":["acme-log-01","acme-log-11"],
         "analyst_task":"tp?"}
    assess = {"label":"true_positive","rationale":"brute force","recommended_next_action":"open",
              "supporting_evidence":["acme-log-01"],"citation_check":{"in_scope":["acme-log-01"],"out_of_scope":[],"valid":True}}
    aid = seed_demo_investigation(st, pol, Session("acme","analyst","aswathy"),
                                  "INC-ACME-7", a, assess, inject_close=True)["pending_action"]
    st.close(); return aid


def client():
    import importlib, app as appmod
    importlib.reload(appmod)
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def test_home_lists_incident():
    seed(); c = client()
    r = c.get("/")
    assert r.status_code == 200 and b"INC-ACME-7" in r.data


def test_incident_shows_pending_and_evidence():
    seed(); c = client()
    r = c.get("/incident/INC-ACME-7")
    assert r.status_code == 200
    assert b"Pending approvals" in r.data and b"brute force" in r.data
    assert b"acme-log-11" in r.data            # original evidence row shown


def test_cross_tenant_incident_404():
    seed(); c = client()
    assert c.get("/incident/INC-GLOBEX-9").status_code == 404


def test_reject_requires_csrf():
    aid = seed(); c = client()
    assert c.post(f"/reject/{aid}").status_code == 400     # no token


def test_reject_keeps_incident_open():
    aid = seed(); c = client()
    with c.session_transaction() as s: s["csrf"] = "tok"
    c.post(f"/reject/{aid}", data={"csrf_token": "tok"})
    st = State(os.environ["SOC_DB"]); inc = st.get_incident("INC-ACME-7"); st.close()
    assert inc["status"] == "contained"       # unchanged (still open)


def test_approve_closes_incident_once():
    aid = seed(); c = client()
    with c.session_transaction() as s: s["csrf"] = "tok"
    c.post(f"/approve/{aid}", data={"csrf_token": "tok"})
    st = State(os.environ["SOC_DB"]); inc = st.get_incident("INC-ACME-7"); st.close()
    assert inc["status"] == "closed" and inc["version"] == 2


if __name__ == "__main__":
    import traceback
    fns = [v for k,v in sorted(globals().items()) if k.startswith("test_")]
    ok=0
    for fn in fns:
        try: fn(); ok+=1; print("PASS",fn.__name__)
        except Exception: print("FAIL",fn.__name__); traceback.print_exc()
    print(f"\n{ok}/{len(fns)} passed"); sys.exit(0 if ok==len(fns) else 1)
