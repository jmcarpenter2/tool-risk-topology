"""tool-risk-topology — static Property-3 analyzer.

Evaluate maligned-AI tool-misuse risk from the *topology* of a toolkit: given
tool signatures alone, decide whether a chokepoint carving shrinks the residual
monitoring burden relative to opaque and atomic carvings.
"""

from .graph import build_graph, choke_free_view, reachable, shortest_len
from .lattice import load_default_lattice, load_lattice
from .metrics import InterfaceMetrics, MonitoringBurden, compute_metrics
from .models import (
    BenignPath,
    CatastrophicEffect,
    Interface,
    Lattice,
    Node,
    Tool,
)
from .partition import BLOCK, CHOKE, RESID, Partition, partition_effects
from .report import KillGateReport, build_report, evaluate_gate
from .schemas import (
    check_information_matching,
    load_default_interfaces,
    load_interface,
)

__version__ = "0.1.0"

__all__ = [
    "BenignPath",
    "CatastrophicEffect",
    "Interface",
    "Lattice",
    "Node",
    "Tool",
    "build_graph",
    "choke_free_view",
    "reachable",
    "shortest_len",
    "load_lattice",
    "load_default_lattice",
    "load_interface",
    "load_default_interfaces",
    "check_information_matching",
    "partition_effects",
    "Partition",
    "BLOCK",
    "CHOKE",
    "RESID",
    "compute_metrics",
    "InterfaceMetrics",
    "MonitoringBurden",
    "build_report",
    "evaluate_gate",
    "KillGateReport",
]
