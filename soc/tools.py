"""The two read tools. search_logs is tenant-scoped BY CONSTRUCTION (the store is
queried with the session tenant, and results are re-checked in Python).
get_incident_record is raw — it does NOT check ownership; that check lives in the
permission layer, which is what lets us compare C0 vs C2.

An unknown alert_id is an explicit error (unknown_alert), never a silent fall-back
to the whole tenant's logs — a bogus id must not widen what evidence is returned."""
import json
from . import datastore
from .types import Session, ToolResult


def search_logs(session: Session, alert_id=None, query=None) -> ToolResult:
    logs = datastore.all_logs(tenant=session.tenant)          # tenant-scoped at the source
    logs = [l for l in logs if l.get("tenant") == session.tenant]   # defence in depth
    if alert_id:
        alert = datastore.get_alert(alert_id)
        if alert is None or alert.get("tenant") != session.tenant:
            return ToolResult(ok=False, error=f"unknown_alert: {alert_id}")
        wanted = set(alert["related_log_ids"])
        logs = [l for l in logs if l["id"] in wanted]
    if query:
        q = query.lower()
        logs = [l for l in logs if q in json.dumps(l).lower()]
    return ToolResult(ok=True, data=logs)


def get_incident_record(session: Session, incident_id) -> ToolResult:
    inc = datastore.get_incident(incident_id)
    if inc is None:
        return ToolResult(ok=False, error="not_found")
    return ToolResult(ok=True, data=inc)   # NOTE: no ownership check here (lives in the permission layer)


def get_file_reputation(session: Session, file_hash=None) -> ToolResult:
    """Enrichment: look up a file hash's reputation (VirusTotal, or offline mock).
    The hash is validated; credentials stay server-side; no file is ever uploaded."""
    from . import enrich
    res = enrich.reputation(file_hash)
    return ToolResult(ok=res.get("ok", False), data=res,
                      error=None if res.get("ok") else res.get("error"))


REGISTRY = {"search_logs": search_logs, "get_incident_record": get_incident_record,
            "get_file_reputation": get_file_reputation}
