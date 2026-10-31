"""The permission layer (C2) and the dispatcher. The model PROPOSES a tool call;
this layer DISPOSES. It decides from facts it looks up ITSELF (the record's real
owner, the session tenant), never from anything the model said.

Two modes, same gate:
  * Legacy (no policy/state): the built-in PermissionLayer handles the read tools —
    exactly as in Stages 1-2. Binary allow/deny.
  * App mode (policy + state supplied): a config-driven PolicyEngine returns one of
    ALLOW / DENY / REQUIRE_APPROVAL, and state-changing proposals are persisted and
    (for closure) held for human approval. Nothing executes on REQUIRE_APPROVAL.
"""
from . import datastore, tools
from .types import (Decision, Session, ToolCall, ToolResult,
                    ALLOW, DENY, REQUIRE_APPROVAL)


class PermissionLayer:
    """Legacy binary gate for the read tools (used when no PolicyEngine is given)."""
    def authorize(self, session: Session, call: ToolCall) -> Decision:
        if call.name == "search_logs":
            return Decision(True, "tenant-scoped by construction")
        if call.name == "get_incident_record":
            inc = datastore.get_incident(call.args.get("incident_id"))
            if inc is None:
                return Decision(True, "record does not exist")
            if inc["tenant"] != session.tenant:
                return Decision(False, f"cross-tenant denied: {call.args.get('incident_id')} "
                                       f"belongs to '{inc['tenant']}', session is '{session.tenant}'")
            return Decision(True, "same-tenant record")
        return Decision(False, f"unknown tool '{call.name}'")


class Dispatcher:
    """Everything the assistant does goes through here. It audits every call.

    policy: a PolicyEngine (app mode) or None (legacy).
    state:  a State store (needed for propose_incident_update) or None.
    """
    def __init__(self, session: Session, enforce_permissions: bool,
                 policy=None, state=None, investigation_id=None):
        self.session = session
        self.enforce = enforce_permissions
        self.permission = PermissionLayer()
        self.policy = policy
        self.state = state
        self.investigation_id = investigation_id
        self.audit = []

    def _authorize(self, request: ToolCall) -> Decision:
        if not self.enforce:
            return Decision(True, "C0 baseline: no enforcement", ALLOW, "C0")
        if self.policy is not None:
            return self.policy.decide(self.session, request)
        return self.permission.authorize(self.session, request)

    def call(self, name, **args) -> ToolResult:
        request = ToolCall(name=name, args=args)
        decision = self._authorize(request)
        self.audit.append({"tool": name, "args": args, "allowed": decision.allowed,
                           "outcome": decision.outcome, "reason": decision.reason,
                           "rule": decision.rule})

        if decision.outcome == DENY:
            return ToolResult(ok=False, error=f"PERMISSION_DENIED: {decision.reason}")

        if decision.outcome == REQUIRE_APPROVAL:
            if self.state is None:
                return ToolResult(ok=False, error="REQUIRE_APPROVAL but no state store configured")
            ttl = self.policy.approval_ttl if self.policy else 3600
            res = self.state.create_pending(self.session, args, decision, ttl=ttl,
                                             inv_id=self.investigation_id)
            return ToolResult(ok=res["ok"], data=res,
                              error=None if res["ok"] else res.get("error"))

        # ALLOW
        if name == "propose_incident_update":
            if self.state is None:
                return ToolResult(ok=False, error="no state store configured")
            res = self.state.apply_now(self.session, args, decision,
                                       inv_id=self.investigation_id)
            return ToolResult(ok=res["ok"], data=res,
                              error=None if res["ok"] else res.get("error"))

        fn = tools.REGISTRY.get(name)
        if fn is None:
            return ToolResult(ok=False, error=f"unknown tool '{name}'")
        return fn(self.session, **args)
