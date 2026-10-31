"""Minimal local analyst console for the SOC assistant.

Shows the incident list, each investigation with its ORIGINAL evidence and the
model's structured assessment, the agent's tool requests and the policy decision
for each, and pending approvals with Approve / Reject controls, plus audit history.

Security notes (demo):
- Jinja2 autoescapes all untrusted text (log messages, model rationale, etc.).
- State-changing routes (approve/reject/run) require a CSRF token tied to the
  session. GET routes change nothing.
- The analyst identity is FIXED (ANALYST_ID) for the demo. This is NOT production
  authentication; a real deployment needs real auth + per-user authorization.
- Bind to 127.0.0.1 only.
"""
import os, secrets
from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort)
from soc.types import Session
from soc.policy import PolicyEngine
from soc.state import State, seed_from_json
from soc.orchestrate import evidence_rows
import soc.datastore as ds
import json, pathlib

DB = os.getenv("SOC_DB", "soc.db")
ANALYST_ID = "analyst:local-demo"          # fixed local identity (NOT production auth)
TENANT = os.getenv("SOC_TENANT", "acme")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(16))

policy = PolicyEngine()


def state():
    # one connection per request is simplest and safe for SQLite/WAL here
    return State(DB)


# ---- CSRF ---------------------------------------------------------------
@app.before_request
def _ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)


@app.context_processor
def _inject_csrf():
    return {"csrf_token": session.get("csrf", "")}


def _check_csrf():
    sent = request.form.get("csrf_token", "")
    if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(400, "bad CSRF token")


# ---- views --------------------------------------------------------------
@app.route("/")
def incidents():
    st = state()
    incs = st.list_incidents(TENANT)
    pend = {}
    for p in st.pending_approvals(TENANT):
        pend[p["incident_id"]] = pend.get(p["incident_id"], 0) + 1
    st.close()
    return render_template("incidents.html", incidents=incs, pending=pend, tenant=TENANT)


@app.route("/incident/<incident_id>")
def incident(incident_id):
    st = state()
    inc = st.get_incident(incident_id)
    if not inc or inc["tenant"] != TENANT:
        st.close(); abort(404)
    invs = [dict(r) for r in st.conn.execute(
        "SELECT * FROM investigations WHERE incident_id=? ORDER BY created_at", (incident_id,))]
    for iv in invs:
        iv["assessment"] = json.loads(iv["assessment_json"]) if iv["assessment_json"] else None
        ev = [r["log_id"] for r in st.conn.execute(
            "SELECT log_id FROM evidence WHERE investigation_id=?", (iv["id"],))]
        iv["evidence"] = evidence_rows(ev)
    pend = [p for p in st.pending_approvals(TENANT) if p["incident_id"] == incident_id]
    for p in pend:
        p["args"] = json.loads(p["args_json"])
    audit = [a for a in st.audit_log() if True]
    # only this incident's audit rows (by action join or incident mention)
    act_ids = {a["id"] for a in st.conn.execute(
        "SELECT id FROM actions WHERE incident_id=?", (incident_id,))}
    audit = [a for a in audit if a["action_id"] in act_ids or a["action_id"] is None]
    st.close()
    return render_template("incident.html", inc=inc, investigations=invs,
                           pending=pend, audit=audit)


@app.route("/approve/<int:action_id>", methods=["POST"])
def approve(action_id):
    _check_csrf()
    st = state()
    d = st.decide_approval(action_id, ANALYST_ID, approve=True)
    if d["ok"]:
        s = Session(TENANT, "analyst", "aswathy")
        r = st.execute_approved(action_id, ANALYST_ID, policy, s)
        flash(f"Approved & executed: {r}" if r["ok"] else f"Approved but NOT executed: {r['error']}",
              "ok" if r.get("ok") else "err")
    else:
        flash(f"Could not approve: {d['error']}", "err")
    inc_id = (st.get_action(action_id) or {}).get("incident_id")
    st.close()
    return redirect(url_for("incident", incident_id=inc_id) if inc_id else url_for("incidents"))


@app.route("/reject/<int:action_id>", methods=["POST"])
def reject(action_id):
    _check_csrf()
    st = state()
    d = st.decide_approval(action_id, ANALYST_ID, approve=False)
    flash(f"Rejected action {action_id}" if d["ok"] else f"Could not reject: {d['error']}",
          "ok" if d["ok"] else "err")
    inc_id = (st.get_action(action_id) or {}).get("incident_id")
    st.close()
    return redirect(url_for("incident", incident_id=inc_id) if inc_id else url_for("incidents"))


@app.route("/audit")
def audit():
    st = state()
    rows = st.audit_log()
    for a in rows:
        a["args"] = a.get("args_json")
    st.close()
    return render_template("audit.html", audit=rows)


if __name__ == "__main__":
    # seed incidents if the db is empty
    st = State(DB)
    if not st.list_incidents():
        seed_from_json(st, json.loads(pathlib.Path("data/incidents.json").read_text()))
    st.close()
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
