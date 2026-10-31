"""Durable SOC state in SQLite: incidents, investigations, evidence refs,
proposed actions, approvals, and audit history. Everything a restart must survive
lives here.

The security-critical routine is execute_approved(): it binds an approval to the
EXACT immutable action and the incident version it was proposed against, rechecks
authorization at execution, and makes approval-consumption + incident-update a
single atomic transaction with WHERE-guards, so a given approval executes
AT MOST ONCE even under repeated clicks or concurrent requests.

Local analyst identity is fixed for the demo (NOT production authentication).
"""
import hashlib, json, sqlite3, time
from .types import Session, ToolCall, REQUIRE_APPROVAL, ALLOW

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, tenant TEXT, title TEXT, status TEXT,
  version INTEGER NOT NULL DEFAULT 1, summary TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS investigations(
  id TEXT PRIMARY KEY, incident_id TEXT, tenant TEXT, alert_id TEXT,
  assessment_json TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS evidence(
  investigation_id TEXT, log_id TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, incident_id TEXT,
  tenant TEXT, actor TEXT, action_type TEXT, args_json TEXT,
  incident_version INTEGER, action_hash TEXT, rationale TEXT,
  status TEXT NOT NULL DEFAULT 'pending', created_at REAL);
CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, action_id INTEGER, status TEXT NOT NULL,
  requested_at REAL, expires_at REAL, decided_by TEXT, decided_at REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, tool TEXT,
  args_json TEXT, outcome TEXT, rule TEXT, reason TEXT, action_id INTEGER);
"""


def action_hash(tenant, incident_id, action_type, args, incident_version) -> str:
    """Immutable fingerprint of an action. Any change (args, type, incident
    version, tenant) yields a different hash, so an approval cannot carry over."""
    canon = json.dumps({"tenant": tenant, "incident_id": incident_id,
                        "action_type": action_type, "args": args,
                        "incident_version": incident_version},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


class State:
    def __init__(self, path="soc.db"):
        # isolation_level=None -> we control transactions explicitly (BEGIN IMMEDIATE)
        self.conn = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    # ---- seeding / reads -------------------------------------------------
    def seed_incident(self, inc: dict):
        self.conn.execute(
            "INSERT OR IGNORE INTO incidents(id,tenant,title,status,version,summary,updated_at)"
            " VALUES(?,?,?,?,1,?,?)",
            (inc["id"], inc["tenant"], inc.get("title", ""), inc.get("status", "open"),
             inc.get("summary", ""), time.time()))

    def ensure_investigation(self, inv_id, incident_id, tenant, alert_id):
        self.conn.execute(
            "INSERT OR IGNORE INTO investigations(id,incident_id,tenant,alert_id,created_at)"
            " VALUES(?,?,?,?,?)", (inv_id, incident_id, tenant, alert_id, time.time()))

    def add_evidence(self, inv_id, log_ids):
        self.conn.executemany("INSERT INTO evidence(investigation_id,log_id) VALUES(?,?)",
                              [(inv_id, lid) for lid in log_ids])

    def save_assessment(self, inv_id, assessment: dict):
        self.conn.execute("UPDATE investigations SET assessment_json=? WHERE id=?",
                          (json.dumps(assessment), inv_id))

    def get_incident(self, incident_id):
        r = self.conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return dict(r) if r else None

    def list_incidents(self, tenant=None):
        if tenant:
            rows = self.conn.execute("SELECT * FROM incidents WHERE tenant=? ORDER BY id",
                                     (tenant,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_action(self, action_id):
        r = self.conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        return dict(r) if r else None

    def get_approval_for(self, action_id):
        r = self.conn.execute("SELECT * FROM approvals WHERE action_id=?", (action_id,)).fetchone()
        return dict(r) if r else None

    def pending_approvals(self, tenant=None):
        q = ("SELECT a.*, ac.incident_id, ac.tenant, ac.action_type, ac.args_json, "
             "ac.actor, ac.rationale, ac.incident_version FROM approvals a "
             "JOIN actions ac ON ac.id=a.action_id WHERE a.status='pending'")
        rows = (self.conn.execute(q + " AND ac.tenant=? ORDER BY a.id", (tenant,))
                if tenant else self.conn.execute(q + " ORDER BY a.id")).fetchall()
        return [dict(r) for r in rows]

    def audit_log(self, incident_id=None):
        rows = self.conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def _audit(self, actor, tool, args, outcome, rule, reason, action_id=None):
        self.conn.execute(
            "INSERT INTO audit(ts,actor,tool,args_json,outcome,rule,reason,action_id)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), actor, tool, json.dumps(args), outcome, rule, reason, action_id))

    # ---- proposing actions ----------------------------------------------
    def apply_now(self, session: Session, args: dict, decision, inv_id=None) -> dict:
        """ALLOW path (comment / escalate): execute immediately, audited.
        comment: no state/version change. escalate: status+version change."""
        incident_id = args.get("incident_id")
        update_type = args.get("update_type")
        actor = f"agent:{session.analyst_id}"
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            inc = self.get_incident(incident_id)
            if inc is None:
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": "unknown_incident"}
            ver = inc["version"]
            ah = action_hash(session.tenant, incident_id, update_type, args, ver)
            cur = self.conn.execute(
                "INSERT INTO actions(investigation_id,incident_id,tenant,actor,action_type,"
                "args_json,incident_version,action_hash,rationale,status,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (inv_id, incident_id, session.tenant, actor, update_type,
                 json.dumps(args), ver, ah, args.get("comment", ""),
                 "applied", time.time()))
            action_id = cur.lastrowid
            if update_type == "escalate":
                self.conn.execute(
                    "UPDATE incidents SET status='escalated', version=version+1, updated_at=?"
                    " WHERE id=? AND version=?", (time.time(), incident_id, ver))
            self._audit(actor, "propose_incident_update", args, ALLOW,
                        decision.rule, decision.reason, action_id)
            self.conn.execute("COMMIT")
        except Exception as e:
            self.conn.execute("ROLLBACK")
            return {"ok": False, "error": f"apply_failed: {e}"}
        new = self.get_incident(incident_id)
        return {"ok": True, "status": "applied", "update_type": update_type,
                "incident_version": new["version"], "action_id": action_id}

    def create_pending(self, session: Session, args: dict, decision, ttl: int,
                       inv_id=None) -> dict:
        """REQUIRE_APPROVAL path (close): record a pending action + approval.
        Nothing is executed. Bound to the incident version seen now."""
        incident_id = args.get("incident_id")
        update_type = args.get("update_type")
        actor = f"agent:{session.analyst_id}"
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            inc = self.get_incident(incident_id)
            if inc is None:
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": "unknown_incident"}
            ver = inc["version"]
            ah = action_hash(session.tenant, incident_id, update_type, args, ver)
            cur = self.conn.execute(
                "INSERT INTO actions(investigation_id,incident_id,tenant,actor,action_type,"
                "args_json,incident_version,action_hash,rationale,status,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (inv_id, incident_id, session.tenant, actor, update_type,
                 json.dumps(args), ver, ah, args.get("comment", ""), "pending", time.time()))
            action_id = cur.lastrowid
            now = time.time()
            self.conn.execute(
                "INSERT INTO approvals(action_id,status,requested_at,expires_at)"
                " VALUES(?,?,?,?)", (action_id, "pending", now, now + ttl))
            self._audit(actor, "propose_incident_update", args, REQUIRE_APPROVAL,
                        decision.rule, decision.reason, action_id)
            self.conn.execute("COMMIT")
        except Exception as e:
            self.conn.execute("ROLLBACK")
            return {"ok": False, "error": f"propose_failed: {e}"}
        return {"ok": True, "status": "pending_approval", "action_id": action_id,
                "incident_version": ver, "reason": decision.reason}

    # ---- approval decisions ---------------------------------------------
    def decide_approval(self, action_id, approver: str, approve: bool) -> dict:
        """Human analyst approves/rejects. The agent cannot do this (it's not a
        tool); we also refuse if the approver is the proposing actor."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            ac = self.get_action(action_id)
            appr = self.get_approval_for(action_id)
            if not ac or not appr:
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "missing"}
            if appr["status"] != "pending":
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": f"not_pending ({appr['status']})"}
            if approver == ac["actor"]:
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": "approver_is_proposer"}
            if time.time() > appr["expires_at"]:
                self.conn.execute("UPDATE approvals SET status='expired' WHERE action_id=?",
                                  (action_id,))
                self.conn.execute("UPDATE actions SET status='expired' WHERE id=?", (action_id,))
                self.conn.execute("COMMIT")
                return {"ok": False, "error": "expired"}
            new_status = "approved" if approve else "rejected"
            self.conn.execute(
                "UPDATE approvals SET status=?, decided_by=?, decided_at=? "
                "WHERE action_id=? AND status='pending'",
                (new_status, approver, time.time(), action_id))
            if not approve:
                self.conn.execute("UPDATE actions SET status='rejected' WHERE id=?", (action_id,))
            self._audit(approver, "approval_decision", {"action_id": action_id},
                        new_status, "approval", f"{approver} {new_status}", action_id)
            self.conn.execute("COMMIT")
        except Exception as e:
            self.conn.execute("ROLLBACK")
            return {"ok": False, "error": f"decide_failed: {e}"}
        return {"ok": True, "status": new_status}

    # ---- execution (the exactly-once, atomic core) ----------------------
    def execute_approved(self, action_id, approver: str, policy=None,
                         session: Session = None) -> dict:
        """Apply an APPROVED action exactly once. Rechecks everything at execution
        and binds to the incident version the action was proposed against."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            ac = self.get_action(action_id)
            appr = self.get_approval_for(action_id)
            if not ac or not appr:
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "missing"}
            if ac["status"] != "pending":                      # exactly-once guard
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": f"action_not_pending ({ac['status']})"}
            if appr["status"] == "consumed":
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "already_consumed"}
            if appr["status"] != "approved":
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": f"not_approved ({appr['status']})"}
            if time.time() > appr["expires_at"]:
                self.conn.execute("UPDATE approvals SET status='expired' WHERE action_id=?",
                                  (action_id,))
                self.conn.execute("UPDATE actions SET status='expired' WHERE id=?", (action_id,))
                self.conn.execute("COMMIT")
                return {"ok": False, "error": "expired"}

            inc = self.get_incident(ac["incident_id"])
            if inc is None:
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "unknown_incident"}
            if inc["tenant"] != ac["tenant"]:
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "tenant_mismatch"}
            # incident changed since proposal -> fresh review required
            if inc["version"] != ac["incident_version"]:
                self.conn.execute("ROLLBACK")
                return {"ok": False, "error": "stale_incident_version"}

            # recheck authorization at execution time
            if policy is not None and session is not None:
                args = json.loads(ac["args_json"])
                d = policy.decide(session, ToolCall("propose_incident_update", args))
                if d.outcome not in (REQUIRE_APPROVAL, ALLOW):
                    self.conn.execute("ROLLBACK")
                    return {"ok": False, "error": f"reauth_denied: {d.reason}"}

            # atomic: consume the approval (only if still 'approved') ...
            cur = self.conn.execute(
                "UPDATE approvals SET status='consumed', decided_by=?, decided_at=? "
                "WHERE action_id=? AND status='approved'",
                (approver, time.time(), action_id))
            if cur.rowcount != 1:                              # lost a race
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "race_lost"}
            # ... and apply the incident change, guarded by the exact version
            new_status = "closed" if ac["action_type"] == "close" else inc["status"]
            cur2 = self.conn.execute(
                "UPDATE incidents SET status=?, version=version+1, updated_at=? "
                "WHERE id=? AND version=?",
                (new_status, time.time(), ac["incident_id"], ac["incident_version"]))
            if cur2.rowcount != 1:
                self.conn.execute("ROLLBACK"); return {"ok": False, "error": "version_conflict"}
            self.conn.execute("UPDATE actions SET status='applied' WHERE id=?", (action_id,))
            self._audit(approver, "execute_action",
                        {"action_id": action_id, "type": ac["action_type"]},
                        "applied", "approval", "approved action executed", action_id)
            self.conn.execute("COMMIT")
        except Exception as e:
            self.conn.execute("ROLLBACK")
            return {"ok": False, "error": f"execute_failed: {e}"}
        new = self.get_incident(ac["incident_id"])
        return {"ok": True, "status": "applied", "incident_status": new["status"],
                "incident_version": new["version"], "action_id": action_id}


def seed_from_json(state: State, incidents: list):
    for inc in incidents:
        state.seed_incident(inc)
