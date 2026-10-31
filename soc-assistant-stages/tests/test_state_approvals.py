"""Stage 3: SQLite state + approval-gated updates. Deterministic, no model/network.
Covers the required cases: comment/escalate/close outcomes, approval reject/approve,
exactly-once execution, stale incident version, expiry, cross-tenant/invalid deny,
approver!=proposer, default-deny, and restart recovery.
Run: python tests/test_state_approvals.py"""
import json, pathlib, sys, tempfile, time, os
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from soc.types import Session
from soc.permission import Dispatcher
from soc.policy import PolicyEngine
from soc.state import State, seed_from_json
import soc.datastore as ds

S = Session(tenant="acme", role="analyst", analyst_id="aswathy")
HUMAN = "analyst:human"            # a human identity, distinct from the agent actor
INCIDENTS = json.loads((pathlib.Path(__file__).resolve().parent.parent / "data" / "incidents.json").read_text())


def fresh():
    d = tempfile.mkdtemp()
    st = State(os.path.join(d, "soc.db"))
    seed_from_json(st, INCIDENTS)
    pol = PolicyEngine()
    return st, pol, os.path.join(d, "soc.db")


def disp(st, pol, enforce=True):
    return Dispatcher(S, enforce_permissions=enforce, policy=pol, state=st,
                      investigation_id="INV-1")


def test_comment_allowed_applies_immediately():
    st, pol, _ = fresh()
    r = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                           update_type="comment", comment="looks related to phishing")
    assert r.ok and r.data["status"] == "applied"
    assert st.get_incident("INC-ACME-7")["version"] == 1       # comment doesn't bump version


def test_escalate_bumps_version():
    st, pol, _ = fresh()
    r = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                           update_type="escalate")
    assert r.ok and st.get_incident("INC-ACME-7")["status"] == "escalated"
    assert st.get_incident("INC-ACME-7")["version"] == 2


def test_close_requires_approval_not_executed():
    st, pol, _ = fresh()
    r = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                           update_type="close")
    assert r.ok and r.data["status"] == "pending_approval"
    inc = st.get_incident("INC-ACME-7")
    assert inc["status"] == "contained" and inc["version"] == 1   # untouched


def test_reject_keeps_incident_open():
    st, pol, _ = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]
    assert st.decide_approval(aid, HUMAN, approve=False)["status"] == "rejected"
    assert st.execute_approved(aid, HUMAN, pol, S)["ok"] is False   # cannot execute a rejected action
    assert st.get_incident("INC-ACME-7")["status"] == "contained"


def test_approve_then_execute_exactly_once():
    st, pol, _ = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]
    st.decide_approval(aid, HUMAN, approve=True)
    r1 = st.execute_approved(aid, HUMAN, pol, S)
    r2 = st.execute_approved(aid, HUMAN, pol, S)                 # repeated click
    assert r1["ok"] and r1["incident_status"] == "closed"
    assert not r2["ok"] and "not_pending" in r2["error"]        # exactly once
    assert st.get_incident("INC-ACME-7")["version"] == 2


def test_cross_tenant_propose_denied():
    st, pol, _ = fresh()
    r = disp(st, pol).call("propose_incident_update", incident_id="INC-GLOBEX-9",
                           update_type="comment", comment="x")
    assert not r.ok and "PERMISSION_DENIED" in r.error


def test_invalid_update_type_denied():
    st, pol, _ = fresh()
    r = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                           update_type="delete")
    assert not r.ok and "PERMISSION_DENIED" in r.error


def test_stale_incident_version_rejected():
    st, pol, _ = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]      # proposed at v1
    disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                       update_type="escalate")                           # incident -> v2
    st.decide_approval(aid, HUMAN, approve=True)
    r = st.execute_approved(aid, HUMAN, pol, S)
    assert not r["ok"] and r["error"] == "stale_incident_version"


def test_expired_approval_never_executes():
    st, pol, _ = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]
    st.decide_approval(aid, HUMAN, approve=True)
    st.conn.execute("UPDATE approvals SET expires_at=? WHERE action_id=?", (time.time() - 1, aid))
    r = st.execute_approved(aid, HUMAN, pol, S)
    assert not r["ok"] and r["error"] == "expired"
    assert st.get_incident("INC-ACME-7")["status"] == "contained"


def test_approver_cannot_be_proposer():
    st, pol, _ = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]
    r = st.decide_approval(aid, "agent:aswathy", approve=True)   # the agent itself
    assert not r["ok"] and r["error"] == "approver_is_proposer"


def test_default_deny_unknown_and_upload():
    st, pol, _ = fresh()
    assert not disp(st, pol).call("run_shell", cmd="rm -rf /").ok
    assert not disp(st, pol).call("upload_file", path="x").ok


def test_restart_recovery():
    st, pol, path = fresh()
    aid = disp(st, pol).call("propose_incident_update", incident_id="INC-ACME-7",
                             update_type="close").data["action_id"]
    st.close()                                   # simulate application restart
    st2 = State(path)
    pend = st2.pending_approvals(tenant="acme")
    assert any(p["action_id"] == aid for p in pend), "pending approval must survive restart"
    st2.decide_approval(aid, HUMAN, approve=True)
    assert st2.execute_approved(aid, HUMAN, pol, S)["ok"]
    assert st2.get_incident("INC-ACME-7")["status"] == "closed"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for fn in fns:
        try: fn(); ok += 1; print(f"PASS {fn.__name__}")
        except Exception: print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{ok}/{len(fns)} passed"); sys.exit(0 if ok == len(fns) else 1)
