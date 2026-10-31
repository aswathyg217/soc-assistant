"""Core types. Session = WHO is acting (trusted). ToolCall = WHAT the model
asked for (untrusted — the args come from the model). Decision = the permission
layer's independent verdict."""
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class Session:
    tenant: str       # which tenant's data this analyst may see
    role: str
    analyst_id: str


@dataclass
class ToolCall:
    name: str
    args: dict


# Three policy outcomes.
ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"


@dataclass
class Decision:
    allowed: bool
    reason: str
    outcome: Optional[str] = None   # allow | deny | require_approval
    rule: Optional[str] = None      # which policy rule decided

    def __post_init__(self):
        if self.outcome is None:
            self.outcome = ALLOW if self.allowed else DENY
        # keep allowed consistent with a 3-valued outcome
        self.allowed = self.outcome == ALLOW


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    error: Optional[str] = None
