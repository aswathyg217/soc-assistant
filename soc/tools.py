"""The two tools. search_logs is tenant-scoped BY CONSTRUCTION (the model can't
name another tenant). get_incident_record is raw — it does NOT check ownership;
that check lives in the permission layer, which is what lets us compare C0 vs C2."""
import json
from . import datastore
from .types import Session, ToolResult


def search_logs(session: Session, alert_id=None, query=None) -> ToolResult:
    logs = [l for l in datastore.all_logs() if l["tenant"] == session.tenant]
    if alert_id:
        alert = datastore.get_alert(alert_id)
        if alert and alert["tenant"] == session.tenant:
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
    return ToolResult(ok=True, data=inc)   # NOTE: no ownership check here


REGISTRY = {"search_logs": search_logs, "get_incident_record": get_incident_record}
