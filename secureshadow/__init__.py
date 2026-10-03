"""
SECURESHADOW - Security Shadow Protection System
Detecting silently degraded security controls.
"""

from .models import (
    Asset,
    SecurityControl,
    Assumption,
    SecurityProperty,
    CommunicationPath,
)
from .graph import SecurityGraph
from .drift import (
    ChangeEvent,
    DriftDetector,
    AssumptionAnalyzer,
)
from .decay import (
    DecayContributor,
    DecayResult,
    DecayCalculator,
)
from .repair import (
    RepairCandidate,
    RepairOptimizer,
)
from .scenarios import create_demo_scenario

__version__ = "0.1.0"
__all__ = [
    "Asset",
    "SecurityControl",
    "Assumption",
    "SecurityProperty",
    "CommunicationPath",
    "SecurityGraph",
    "ChangeEvent",
    "DriftDetector",
    "AssumptionAnalyzer",
    "DecayContributor",
    "DecayResult",
    "DecayCalculator",
    "RepairCandidate",
    "RepairOptimizer",
    "create_demo_scenario",
]
