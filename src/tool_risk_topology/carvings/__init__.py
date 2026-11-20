"""runnable interface carvings over one shared capability backend.

The pure pieces (schemas, info-matching, the carving definitions) import without
any service client; the backend imports psycopg/minio/httpx lazily.
"""

from .backend import CapabilityBackend, CapabilityError
from .base import CarvingServer, CarvingTool, ToolParam, ToolResult
from .info_match import InfoMatchReport, run_info_match, runnable_to_interface
from .registry import CARVING_IDS, build_all, build_carving

__all__ = [
    "CapabilityBackend",
    "CapabilityError",
    "CarvingServer",
    "CarvingTool",
    "ToolParam",
    "ToolResult",
    "build_carving",
    "build_all",
    "CARVING_IDS",
    "run_info_match",
    "InfoMatchReport",
    "runnable_to_interface",
]
