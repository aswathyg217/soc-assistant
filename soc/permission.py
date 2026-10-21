"""The permission layer (C2) and the dispatcher. The model PROPOSES a tool call;
this layer DISPOSES. It decides from facts it looks up ITSELF (the record's real
owner), never from anything the model said — which is why an injection cannot
talk past it."""
from . import datastore, tools
from .types import Decision, Session, ToolCall, ToolResult


class PermissionLayer:
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
    """Everything the assistant does goes through here. It audits every call."""
    def __init__(self, session: Session, enforce_permissions: bool):
        self.session = session
        self.enforce = enforce_permissions
        self.permission = PermissionLayer()
        self.audit = []

    def call(self, name, **args) -> ToolResult:
        request = ToolCall(name=name, args=args)
        if self.enforce:
            decision = self.permission.authorize(self.session, request)
        else:
            decision = Decision(True, "C0 baseline: no enforcement")
        self.audit.append({"tool": name, "args": args,
                           "allowed": decision.allowed, "reason": decision.reason})
        if not decision.allowed:
            return ToolResult(ok=False, error=f"PERMISSION_DENIED: {decision.reason}")
        fn = tools.REGISTRY.get(name)
        if fn is None:
            return ToolResult(ok=False, error=f"unknown tool '{name}'")
        return fn(self.session, **args)
