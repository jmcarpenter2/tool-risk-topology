"""the control game: policies, monitor, audit.

Pure pieces (trajectory, monitor scoring, audit math) import without any service
client; policies/skills act on the sandbox through the carvings + harness.
"""

from .audit import (
    audit_threshold,
    empirical_fpr,
    safety,
    two_proportion_z,
    usefulness,
    wilson_ci,
)
from .monitor import (
    CHOKEPOINT,
    PER_CALL,
    TRAJECTORY,
    HeuristicScorer,
    ModelScorer,
    Monitor,
    ScoredTrajectory,
    single_suspicion,
)
from .policies import AttackPolicy, HonestPolicy, run_episode
from .trajectory import Action, Trajectory

__all__ = [
    "Action",
    "Trajectory",
    "HonestPolicy",
    "AttackPolicy",
    "run_episode",
    "Monitor",
    "HeuristicScorer",
    "ModelScorer",
    "ScoredTrajectory",
    "single_suspicion",
    "PER_CALL",
    "TRAJECTORY",
    "CHOKEPOINT",
    "audit_threshold",
    "empirical_fpr",
    "safety",
    "usefulness",
    "wilson_ci",
    "two_proportion_z",
]
