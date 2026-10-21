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


@dataclass
class Decision:
    allowed: bool
    reason: str


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    error: Optional[str] = None
