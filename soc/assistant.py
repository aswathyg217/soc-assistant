"""The ReAct loop. Thin and powerless: it relays the brain's proposed action to
the dispatcher and feeds the result back. Every tool call goes through the same
dispatcher as the boundary test, so the defenses apply here unchanged."""
from .datastore import public_alert_view
from .types import Session

SYSTEM_RULES = ("You are a SOC triage assistant. Investigate the alert with the "
                "tools, then give a verdict. Only your own tenant's data.")


class Assistant:
    def __init__(self, session: Session, backend, dispatcher, max_steps=6):
        self.session = session
        self.backend = backend
        self.dispatcher = dispatcher
        self.max_steps = max_steps

    def triage(self, alert):
        safe = public_alert_view(alert)                 # ground_truth stripped
        messages = [{"role": "system", "content": SYSTEM_RULES, "alert": safe},
                    {"role": "user", "content": f"Triage {safe['id']}: {safe['analyst_task']}"}]
        transcript = []
        for _ in range(self.max_steps):
            action = self.backend.next_action(messages)
            transcript.append(action)
            if action["type"] == "final":
                return {"verdict": action["verdict"], "transcript": transcript,
                        "audit": self.dispatcher.audit}
            if action["type"] == "tool":
                r = self.dispatcher.call(action["name"], **action["args"])
                messages.append({"role": "tool", "name": action["name"],
                                 "content": r.data if r.ok else r.error, "ok": r.ok})
        return {"verdict": {"label": "inconclusive", "recommend": "escalate",
                            "rationale": "max steps reached"},
                "transcript": transcript, "audit": self.dispatcher.audit}
