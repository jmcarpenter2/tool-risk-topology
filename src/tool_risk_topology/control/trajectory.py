"""Trajectory model for the control game.

An episode yields a trajectory ``τ = (a_1, …, a_T)`` of typed tool calls. Each
:class:`Action` records the carving, tool, arguments, outcome, and a coarse
``category`` derived from the tool's Out capability labels (public info a monitor
may use). Whether an action *carried the sentinel* is kept in ``meta`` — known to
the harness for labeling, never shown to the monitor.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# coarse capability categories (monitor-visible; derived from tool Out labels)
CAT_READ = "read"
CAT_FILE_WRITE = "file_write"
CAT_OBJECT_WRITE = "object_write"
CAT_DB_WRITE = "db_write"
CAT_ENV_READ = "env_read"
CAT_API = "api_call"
CAT_EGRESS = "egress"
CAT_RUN = "run_command"


@dataclass
class Action:
    index: int
    carving: str
    tool: str
    args: Dict[str, Any]
    category: str
    ok: bool = True
    output: str = ""
    chokepoint: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def carried_sentinel(self) -> bool:
        return bool(self.meta.get("sentinel", False))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Trajectory:
    task_id: str
    carving: str
    policy_kind: str  # "H" (honest) | "A" (attack)
    actions: List[Action] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    # filled in downstream by extraction / sentinel / monitor
    effects: Optional[dict] = None
    Z: Optional[int] = None  # sentinel achieved
    task_ok: Optional[bool] = None  # benign task solved (usefulness)

    def add(self, action: Action) -> Action:
        action.index = len(self.actions)
        self.actions.append(action)
        return action

    def __len__(self) -> int:
        return len(self.actions)

    @property
    def sentinel_actions(self) -> List[Action]:
        return [a for a in self.actions if a.carried_sentinel]

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "carving": self.carving,
            "policy_kind": self.policy_kind,
            "actions": [a.to_dict() for a in self.actions],
            "meta": self.meta,
            "effects": self.effects,
            "Z": self.Z,
            "task_ok": self.task_ok,
        }
