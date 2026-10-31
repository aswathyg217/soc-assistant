"""Ties an investigation to the durable state: run the gated agent on an alert,
persist the evidence it saw and the assessment it produced, and let any
incident-update proposals flow through the gateway into the approval queue.

run_investigation() is the live path (needs Groq). seed_demo_investigation() is a
model-free path that populates the same state for the UI/demo without a key.
"""
import uuid
from .types import Session
from .permission import Dispatcher
from . import datastore


def _inv_id(alert_id):
    return f"INV-{alert_id}-{uuid.uuid4().hex[:6]}"


def evidence_rows(log_ids):
    """Fetch the ORIGINAL evidence rows for display (unfiltered by any model text)."""
    by_id = {l["id"]: l for l in datastore.all_logs()}
    return [by_id[i] for i in log_ids if i in by_id]


def run_investigation(state, policy, session: Session, incident_id, alert, llm=None,
                      harden=False):
    """Live: run the LangGraph agent, gated by policy+state, and persist results."""
    from .agent import GatedAgent
    inv_id = _inv_id(alert["id"])
    state.ensure_investigation(inv_id, incident_id, session.tenant, alert["id"])
    disp = Dispatcher(session, enforce_permissions=True, policy=policy, state=state,
                      investigation_id=inv_id)
    result = GatedAgent(session, disp, harden=harden, llm=llm).triage(alert)
    state.add_evidence(inv_id, result.get("evidence_ids", []))
    state.save_assessment(inv_id, result["assessment"])
    return {"investigation_id": inv_id, "result": result}


def seed_demo_investigation(state, policy, session: Session, incident_id, alert,
                            assessment, inject_close=False):
    """Model-free: record an investigation, its evidence and a structured assessment,
    and optionally push a closure proposal through the gate (-> pending approval),
    simulating a closure-injection. Exercises the REAL dispatcher, no model needed."""
    inv_id = _inv_id(alert["id"])
    state.ensure_investigation(inv_id, incident_id, session.tenant, alert["id"])
    state.add_evidence(inv_id, alert.get("related_log_ids", []))
    state.save_assessment(inv_id, assessment)
    pending_action = None
    if inject_close:
        disp = Dispatcher(session, enforce_permissions=True, policy=policy, state=state,
                          investigation_id=inv_id)
        r = disp.call("propose_incident_update", incident_id=incident_id,
                      update_type="close", comment="(injected) close as benign maintenance")
        if r.ok:
            pending_action = r.data.get("action_id")
    return {"investigation_id": inv_id, "pending_action": pending_action}
