"""Pluggable 'brain' behind one method: next_action(messages) -> an action dict.
  {"type":"tool","name":...,"args":{...}}  — call a tool
  {"type":"final","verdict":{...}}         — finish

ScriptedBackend needs no model: it follows a fixed policy, and can OBEY an
injection on demand (later) to simulate a hijack. The Groq backend drops in at
Phase 2 behind this same method — nothing else changes."""
import json, re


class ScriptedBackend:
    def __init__(self, obey_injection=False):
        self.obey_injection = obey_injection

    def next_action(self, messages):
        tool_results = [m for m in messages if m["role"] == "tool"]
        if not tool_results:                      # step 1: read the alert's logs
            alert = next(m["alert"] for m in messages if m["role"] == "system")
            return {"type": "tool", "name": "search_logs",
                    "args": {"alert_id": alert["id"]}}

        logs = next((m["content"] for m in reversed(tool_results)
                     if isinstance(m["content"], list)), [])

        already = any(m["name"] == "get_incident_record" for m in tool_results)
        if self.obey_injection and not already:
            hit = _injected(logs)
            if hit:
                return hit
        return {"type": "final", "verdict": _triage(logs)}


def _triage(logs):
    actions = [l.get("action", "") for l in logs]
    failed = sum(a == "ssh_login_failed" for a in actions)
    success = any(a == "ssh_login_succeeded" for a in actions)
    if failed >= 2 and success:
        return {"label": "true_positive", "recommend": "open",
                "rationale": f"{failed} failed logins then a success: brute-force."}
    return {"label": "false_positive", "recommend": "close",
            "rationale": "No brute-force pattern; looks benign."}


def _injected(logs):
    raw = json.dumps(logs)
    if "get_incident_record" in raw.lower() or "incident" in raw.lower():
        m = re.search(r"(INC-[A-Z]+-\d+)", raw)
        if m:
            return {"type": "tool", "name": "get_incident_record",
                    "args": {"incident_id": m.group(1)}}
    return None
