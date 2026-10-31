"""Config-driven policy engine. Loads and VALIDATES policy.yaml, then maps a
proposed tool call to one of three outcomes: ALLOW, DENY, REQUIRE_APPROVAL.

Enforcement is in code; the config only expresses the allow/deny/approval mapping
and the human-readable reasons. The engine decides cross-tenant and update-type
questions from TRUSTED facts (the record's real owner, the session tenant), never
from anything the model said. Default is deny."""
import pathlib
from . import datastore
from .types import Decision, Session, ToolCall, ALLOW, DENY, REQUIRE_APPROVAL

_VALID_OUTCOMES = {"allow", "deny", "allow_same_tenant"}
_VALID_UPDATE_TYPES = {"comment", "escalate", "close"}


class PolicyError(Exception):
    pass


def _validate(cfg: dict):
    if cfg.get("default") != "deny":
        raise PolicyError("policy default must be 'deny'")
    tools = cfg.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise PolicyError("policy must define a non-empty 'tools' map")
    for name, rule in tools.items():
        if "by_update_type" in rule:
            for t, o in rule["by_update_type"].items():
                if t not in _VALID_UPDATE_TYPES:
                    raise PolicyError(f"{name}: unknown update_type '{t}'")
                if o not in ("allow", "require_approval", "deny"):
                    raise PolicyError(f"{name}.{t}: bad outcome '{o}'")
        elif rule.get("outcome") not in _VALID_OUTCOMES:
            raise PolicyError(f"{name}: bad outcome '{rule.get('outcome')}'")
    if not isinstance(cfg.get("approval_ttl_seconds", 3600), int):
        raise PolicyError("approval_ttl_seconds must be an integer")
    return cfg


def load_policy(path=None) -> dict:
    import yaml
    if path is None:
        path = pathlib.Path(__file__).resolve().parent.parent / "policy.yaml"
    cfg = yaml.safe_load(pathlib.Path(path).read_text())
    return _validate(cfg)


class PolicyEngine:
    def __init__(self, config=None, path=None):
        self.cfg = config if config is not None else load_policy(path)
        self.tools = self.cfg["tools"]

    @property
    def approval_ttl(self) -> int:
        return int(self.cfg.get("approval_ttl_seconds", 3600))

    def decide(self, session: Session, call: ToolCall) -> Decision:
        rule = self.tools.get(call.name)
        if rule is None:
            return Decision(False, f"no rule for tool '{call.name}' (default deny)",
                            DENY, "default-deny")

        # per-update-type state-changing proposals
        if "by_update_type" in rule:
            return self._decide_update(session, call, rule)

        outcome = rule["outcome"]
        reason = rule.get("reason", call.name)
        if outcome == "allow":
            return Decision(True, reason, ALLOW, call.name)
        if outcome == "deny":
            return Decision(False, reason, DENY, call.name)
        if outcome == "allow_same_tenant":
            return self._decide_same_tenant(session, call, reason)
        return Decision(False, f"unhandled outcome '{outcome}'", DENY, call.name)

    def _decide_same_tenant(self, session, call, reason) -> Decision:
        inc = datastore.get_incident(call.args.get("incident_id"))
        if inc is None:
            # unknown record: nothing to leak; allow so the tool returns not_found
            return Decision(True, "record does not exist", ALLOW, call.name)
        if inc["tenant"] != session.tenant:
            return Decision(
                False,
                f"cross-tenant denied: {call.args.get('incident_id')} belongs to "
                f"'{inc['tenant']}', session is '{session.tenant}'",
                DENY, call.name)
        return Decision(True, reason, ALLOW, call.name)

    def _decide_update(self, session, call, rule) -> Decision:
        args = call.args
        incident_id = args.get("incident_id")
        update_type = args.get("update_type")
        inc = datastore.get_incident(incident_id)
        # cross-tenant / out-of-scope proposals are denied
        if inc is not None and inc["tenant"] != session.tenant:
            return Decision(False,
                            f"cross-tenant denied: {incident_id} is not tenant "
                            f"'{session.tenant}'", DENY, "propose_incident_update")
        mapping = rule["by_update_type"]
        if update_type not in mapping:
            return Decision(False, rule.get("reason_denied_type", "invalid update_type"),
                            DENY, "propose_incident_update")
        outcome = mapping[update_type]
        if outcome == "allow":
            return Decision(True, rule.get("reason_allow", "permitted"),
                            ALLOW, f"propose_incident_update:{update_type}")
        if outcome == "require_approval":
            return Decision(False, rule.get("reason_approval", "approval required"),
                            REQUIRE_APPROVAL, f"propose_incident_update:{update_type}")
        return Decision(False, "denied update_type", DENY, "propose_incident_update")
